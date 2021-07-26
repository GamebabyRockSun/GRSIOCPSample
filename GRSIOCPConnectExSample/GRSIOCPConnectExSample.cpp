#include <tchar.h>
#define WIN32_LEAN_AND_MEAN	
#include <windows.h>
#include <strsafe.h>
#include <Winsock2.h>
#include <Mstcpip.h>
#include <process.h>    //for _beginthreadex
#include <atlcoll.h>

#include "../Public/GRSWinSock2Fun.h"

#pragma comment( lib, "Ntdll.lib" )

// 用于命令行输出的宏定义
#define GRS_USEPRINTF() TCHAR pOutBufT[1024] = {};CHAR pOutBufA[1024] = {};
#define GRS_PRINTF(...) \
    StringCchPrintf(pOutBufT,1024,__VA_ARGS__);\
    WriteConsole(GetStdHandle(STD_OUTPUT_HANDLE),pOutBufT,lstrlen(pOutBufT),nullptr,nullptr);
#define GRS_PRINTFA(...) \
    StringCchPrintfA(pOutBufA,1024,__VA_ARGS__);\
    WriteConsoleA(GetStdHandle(STD_OUTPUT_HANDLE),pOutBufA,lstrlenA(pOutBufA),nullptr,nullptr);

// 内存分配的宏定义
#define GRS_ALLOC(sz)		HeapAlloc(GetProcessHeap(),0,sz)
#define GRS_CALLOC(sz)		HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sz)
#define GRS_CREALLOC(p,sz)	HeapReAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,p,sz)
#define GRS_SAFEFREE(p)		if(nullptr != p){HeapFree(GetProcessHeap(),0,p);p=nullptr;}

// 启动线程的宏定义
#define GRS_BEGINTHREAD(Fun,Param) (HANDLE)_beginthreadex(nullptr,0,(_beginthreadex_proc_type)(Fun),(Param),0,nullptr)

// 自定义Sleep 时间精度更高
#define GRS_SLEEP(dwMilliseconds)  WaitForSingleObject(GetCurrentThread(),dwMilliseconds)

// 一些默认参数，这些参数可以定义到配置文件中去，比如INI、XML、Lua等
#define GRS_SERVER_IP                   _T("127.0.0.1")  // 服务器的IP
#define GRS_SERVER_PORT                 8080    // 服务器的端口
#define GRS_DATA_BUFSIZE_DEFAULT        4096    // 默认数据缓冲大小
#define GRS_DATA_BUF_GROW_SIZE          4096    // 数据缓冲增长大小
#define GRS_THREAD_POOL_THREAD_COUNT    0       // 默认启动的线程数量，当为0时，自动根据系统逻辑内核数量创建等量的线程
#define GRS_MAX_CONNECT_SOCKET          1       // 最大同时侦听的SOCKET数，实质是并行的Accept数量，循环使用就可以完成高并发响应

// 以下是自定义Overlapped结构的相关宏和结构体定义
// 注意保持其内部数据的原子性，不要牵扯全局变量或跨域跨线程的定义
// 否则必须要进行低效的跨线程同步访问，就失去了使用多线程SOCKET池的意义
#define GRS_ADDR_STR_LEN            36
#define GRS_WSABUF_COUNT_DEFAULT    1

struct ST_GRS_MY_WSAOVERLAPPED
{
    WSAOVERLAPPED m_wsaOL;
    SOCKET        m_skConnect;

    ULONG         m_ulAddrLocalLen;
    ULONG         m_ulAddrRemotLen;
    TCHAR         m_pszAddrLocal[GRS_ADDR_STR_LEN];
    TCHAR         m_pszAddrRemot[GRS_ADDR_STR_LEN];

    INT           m_iLocalLen;
    SOCKADDR_IN   m_saLocal;
    INT           m_iRemoteLen;
    SOCKADDR_IN   m_saRemote;

    LONG          m_lOperation;     // 投递的操作类型(FD_READ/FD_WRITE等)

    DWORD		  m_dwTrasBytes;    // 为WSASent和WSARecv准备的参数
    DWORD         m_dwFlags;        // 为WSARecv准备的

    WSABUF        m_wsaBuf;         // WinSock2函数家族特有的传输缓冲结构体，不要被CHAR*类型迷惑，缓冲中可以放任意数据，而不是说只能传ASSIC字符
    SIZE_T        m_szBufLen;       // 数据缓冲长度
    PVOID         m_pBuf;           // 投递操作时的数据缓冲
};

typedef CAtlArray<HANDLE> CGRSHandleArray;
typedef CAtlArray<SOCKET> CGRSSocketArray;
typedef CAtlArray<ST_GRS_MY_WSAOVERLAPPED*> CGRSOverlappedArray;

//IOCP线程池线程函数
unsigned int __stdcall GRSIOCPThread(void* lpParameter);

CGRSWinSock2Fun* g_pMSWInSock2Fun;

// IOCP句柄
HANDLE  g_hIOCP = nullptr;
// WinSock2 函数接口类
CGRSWinSock2Fun* g_pWinSock2Fun = nullptr;
// 线程句柄数组
CGRSHandleArray g_arThread;
// SOCKET 句柄数组
CGRSSocketArray g_arSocket;
// 自定义Overlapped结构体指针数组
CGRSOverlappedArray g_arOverlapped;

int _tmain()
{
    int iRet = 0;
    try
    {
        GRS_USEPRINTF();
        DWORD   dwProcessorCnt  = GRS_THREAD_POOL_THREAD_COUNT;
        INT     iMaxConnectEx   = GRS_MAX_CONNECT_SOCKET;
        SIZE_T  szDefaultBufLen = GRS_DATA_BUFSIZE_DEFAULT;
        
        int result = 0;
        ST_GRS_MY_WSAOVERLAPPED* pOLConnectEx = nullptr;
        const int on = 1;

        if ( 0 == dwProcessorCnt )
        {
            SYSTEM_INFO si = {};
            ::GetSystemInfo(&si);
            dwProcessorCnt = si.dwNumberOfProcessors;
        }

        g_pMSWInSock2Fun = CGRSWinSock2Fun::GetInstance();

        //创建IOCP内核对象,允许最大并发CPU个数个线程
        g_hIOCP = ::CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, dwProcessorCnt);
        if (nullptr == g_hIOCP)
        {
            GRS_PRINTF(_T("[%8u]: 完成端口创建失败，程序将退出！\n"), GetCurrentThreadId());
            AtlThrowLastWin32();
        }

        //实际创建2倍CPU个数个线程
        for (DWORD i = 0; i < dwProcessorCnt; i++)
        {
            g_arThread.Add(GRS_BEGINTHREAD(GRSIOCPThread, g_hIOCP));
        }
        GRS_PRINTF(_T("[%8u]: [%u]个线程被启动。\n"), GetCurrentThreadId(), g_arThread.GetCount());


        sockaddr_in stServerIP = {};
        stServerIP.sin_family = AF_INET;
        stServerIP.sin_port = htons(GRS_SERVER_PORT); // 注意互联网上是大端序
        LPCTSTR pszTerminator = _T("");
        // 默认是绑到本地地址（0.0.0.0) 在多网口多IP系统中，这相当于在所有的IP上都监听
        ::RtlIpv4StringToAddress(GRS_SERVER_IP, TRUE, &pszTerminator, &stServerIP.sin_addr);
        
        sockaddr_in stLocalIP = {};
        stLocalIP.sin_family = AF_INET;
        stLocalIP.sin_addr.s_addr = INADDR_ANY; // 本地绑定的地址放在默认的 0.0.0.0 这样可以通过所有可能的路由途径链接到服务端
        stLocalIP.sin_port = htons((short)0);	// 使用0让系统自动分配

        //发起AcceptEx调用
        for (int i = 0; i < iMaxConnectEx; i++)
        {
            pOLConnectEx = (ST_GRS_MY_WSAOVERLAPPED*)GRS_CALLOC(sizeof(ST_GRS_MY_WSAOVERLAPPED));

            g_arOverlapped.Add(pOLConnectEx);
            pOLConnectEx->m_ulAddrLocalLen = GRS_ADDR_STR_LEN;
            pOLConnectEx->m_ulAddrRemotLen = GRS_ADDR_STR_LEN;
            pOLConnectEx->m_iLocalLen = sizeof(SOCKADDR_IN);
            pOLConnectEx->m_saLocal = {};
            pOLConnectEx->m_iRemoteLen = sizeof(SOCKADDR_IN);
            pOLConnectEx->m_saRemote = {};
            pOLConnectEx->m_lOperation = FD_CONNECT;
            pOLConnectEx->m_szBufLen = szDefaultBufLen;
            pOLConnectEx->m_pBuf = GRS_CALLOC(pOLConnectEx->m_szBufLen);

            pOLConnectEx->m_skConnect = ::WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, WSA_FLAG_OVERLAPPED);

            g_arSocket.Add(pOLConnectEx->m_skConnect);

            //将SOCKET句柄与完成端口对象绑定
            ::CreateIoCompletionPort((HANDLE)pOLConnectEx->m_skConnect, g_hIOCP, 0, 0);

            //允许地址重用
            //::setsockopt(pOLConnectEx->m_skConnect, SOL_SOCKET, SO_REUSEADDR, (char*)&on, sizeof(on));

            // ConnectEx要求先要绑定一个本地的地址和端口
            result = ::bind(pOLConnectEx->m_skConnect, (LPSOCKADDR)&stLocalIP, sizeof(SOCKADDR_IN));

            ::getsockname(pOLConnectEx->m_skConnect, (SOCKADDR*)&pOLConnectEx->m_saLocal, &pOLConnectEx->m_iLocalLen);

            RtlIpv4AddressToStringEx(&pOLConnectEx->m_saLocal.sin_addr
                , pOLConnectEx->m_saLocal.sin_port
                , pOLConnectEx->m_pszAddrLocal
                , &pOLConnectEx->m_ulAddrLocalLen);

            GRS_PRINTF(_T("[%8u]: SOCKET[0x%08x]绑定被分配地址为[%s]。\n")
                , GetCurrentThreadId()
                , pOLConnectEx->m_skConnect
                , pOLConnectEx->m_pszAddrLocal);            

            CopyMemory(&pOLConnectEx->m_saRemote, &stServerIP, sizeof(SOCKADDR_IN));

            RtlIpv4AddressToStringEx(&pOLConnectEx->m_saRemote.sin_addr
                , pOLConnectEx->m_saRemote.sin_port
                , pOLConnectEx->m_pszAddrRemot
                , &pOLConnectEx->m_ulAddrRemotLen);

            if (!g_pMSWInSock2Fun->ConnectEx(pOLConnectEx->m_skConnect
                , (SOCKADDR*)&pOLConnectEx->m_saRemote
                , pOLConnectEx->m_iRemoteLen
                , nullptr
                , 0
                , &pOLConnectEx->m_dwTrasBytes
                , (LPOVERLAPPED)pOLConnectEx))
            {
                int iError = WSAGetLastError();
                if (ERROR_IO_PENDING != iError
                    && WSAECONNRESET != iError)
                {
                    if (INVALID_SOCKET != pOLConnectEx->m_skConnect)
                    {
                        ::closesocket(pOLConnectEx->m_skConnect);
                        pOLConnectEx->m_skConnect = INVALID_SOCKET;
                    }
                    GRS_SAFEFREE(pOLConnectEx->m_pBuf);
                    GRS_SAFEFREE(pOLConnectEx);

                    g_arSocket.SetAt(i, INVALID_SOCKET);
                    g_arOverlapped.SetAt(i, nullptr);

                    GRS_PRINTF(_T("[%8u]:  调用ConnectEx失败,错误码:%d\n"), GetCurrentThreadId(), iError);
                    continue;
                }

            }
            GRS_PRINTF(_T("[%8u]: (%d)SOCKET [0x%08x] ConnectEx to IP[%s]...\n")
                , GetCurrentThreadId()
                , i
                , pOLConnectEx->m_skConnect
                , pOLConnectEx->m_pszAddrRemot
            );
        }

        //主线程进入等待状态
        GRS_PRINTF(_T("[%8u]: 主线程进入等待状态，按\'q\'键退出。\n"), GetCurrentThreadId());
        //主线程进入等待状态
        INPUT_RECORD sinfo = {};
        DWORD recnum = 0;
        HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
        while (ReadConsoleInput(hIn, &sinfo, 1, &recnum))
        {
            if (sinfo.EventType != KEY_EVENT)
            {
                continue;//无视其他类型输入
            }
            //判断按键状态(以防按键被触发两次)
            if (sinfo.Event.KeyEvent.uChar.UnicodeChar == L'q')
            {
                break;
            }
        }
        GRS_PRINTF(_T("[%8u]: 主线程接到退出消息......\n"), GetCurrentThreadId());

        ST_GRS_MY_WSAOVERLAPPED CloseOL = {};
        //向IOCP线程池发送退出消息 利用标志FD_CLOSE标志
        CloseOL.m_skConnect = INVALID_SOCKET;
        CloseOL.m_lOperation = FD_CLOSE;

        for (DWORD i = 0; i < dwProcessorCnt; i++)
        {
            ::PostQueuedCompletionStatus(g_hIOCP, 0, 0, (LPOVERLAPPED)&CloseOL);
        }
        ::WaitForMultipleObjects((DWORD)g_arThread.GetCount(), g_arThread.GetData(), TRUE, INFINITE);

        for (DWORD i = 0; i < dwProcessorCnt; i++)
        {
            ::CloseHandle(g_arThread[i]);
        }
        g_arThread.RemoveAll();

        ::CloseHandle(g_hIOCP);

        //释放SOCKET及ST_GRS_MY_WSAOVERLAPPED资源
        for (int i = 0; i < g_arOverlapped.GetCount(); i++)
        {
            GRS_SAFEFREE(g_arOverlapped[i]->m_pBuf);
            GRS_SAFEFREE(g_arOverlapped[i]);
        }
        g_arOverlapped.RemoveAll();

        for (int i = 0; i < g_arSocket.GetCount(); i++)
        {
            closesocket(g_arSocket[i]);
        }
        g_arSocket.RemoveAll();
    }
    catch (CAtlException& e)
    {//发生了COM异常
        e;
        iRet = e.m_hr;
    }
    catch (...)
    {
        iRet = -1;
    }

    CGRSWinSock2Fun::Destory();
    _tsystem(_T("PAUSE"));

    return iRet;
}

//IOCP线程池线程函数
unsigned int __stdcall GRSIOCPThread(void* lpParameter)
{
    int iRet = 0;
    GRS_USEPRINTF();
    try
    {       
        HANDLE hIOCP = (HANDLE)lpParameter;
        ULONG_PTR       ulKey = 0;
        OVERLAPPED*     lpOverlapped = nullptr;
        ST_GRS_MY_WSAOVERLAPPED* pMyOl = nullptr;
        DWORD           dwBytesTransfered = 0;
        DWORD           dwFlags = 0;
        
        WCHAR pszSendMsg[] = _T("捻一指流沙 池鱼溅起浪花 待我醉马挥剑 斩落晚残霞\
            梦见紫金甲 头戴凤批纱  黄梁一梦 太虚幻浮夸 聊一篇闲话 布衣越冬夏  待我功成名就 西山纵肥马 凭酒论天下 喊声小二续茶\
            明月邀窗 故佯装潇洒  我饮过风 咽过沙 浪子无钱逛酒家 闻琵琶 谁人画  不再春风如寒鸦 我饮过风 咽过沙 浪迹天涯浮云下\
            叹流年 似黄花 问过苍天无人答 我饮过风 咽过沙 浪子无钱逛酒家 闻琵琶 谁人画 不再春风如寒鸦 我饮过风 咽过沙  浪迹天涯浮云下\
            叹流年 似黄花  问过苍天无人答 聊一篇闲话 布衣越冬夏 待我功成名就 西山纵肥马 凭酒论天下 喊声小二续茶 明月邀窗 故佯装潇洒\
            我饮过风 咽过沙 浪子无钱逛酒家 闻琵琶 谁人画 不再春风如寒鸦 我饮过风 咽过沙 浪迹天涯浮云下 叹流年 似黄花 问过苍天无人答\
            我饮过风 咽过沙 浪子无钱逛酒家 闻琵琶 谁人画 不再春风如寒鸦 我饮过风 咽过沙 浪迹天涯浮云下 叹流年 似黄花 问过苍天无人答\
            我饮过风 咽过沙 浪子无钱逛酒家 闻琵琶 谁人画 不再春风如寒鸦 我饮过风 咽过沙 浪迹天涯浮云下 叹流年 似黄花 问过苍天无人答\
            我饮过风 咽过沙 浪子无钱逛酒家 闻琵琶 谁人画 不再春风如寒鸦 我饮过风 咽过沙 浪迹天涯浮云下 叹流年 似黄花 问过苍天无人答！");
        DWORD dwMsgLen = sizeof(pszSendMsg);

        BOOL   bRet = TRUE;
        BOOL   bLoop = TRUE;

        while (bLoop)
        {
            bRet = GetQueuedCompletionStatus(hIOCP, &dwBytesTransfered, (PULONG_PTR)&ulKey, &lpOverlapped, INFINITE);
            pMyOl = CONTAINING_RECORD(lpOverlapped, ST_GRS_MY_WSAOVERLAPPED, m_wsaOL);

            ATLASSERT(nullptr != hIOCP && g_hIOCP == hIOCP);

            if ( FALSE == bRet )
            {
                if ( nullptr != lpOverlapped )
                {// 可能是TIMER_WAIT 所以重连一下
                    GRS_SLEEP(1000);

					GRS_PRINTF(_T("[%8u]: SOCKET[0x%08x] 发生错误：0x%08X，忽略，重新发起连接，远端IP[%s]。\n")
						, GetCurrentThreadId()
						, pMyOl->m_skConnect
						, pMyOl->m_wsaOL.Internal
						, pMyOl->m_pszAddrRemot);

					//pMyOl->m_dwFlags = 0;
					//pMyOl->m_lOperation = FD_CONNECT;

					//// 回收成功,重新丢入连接池
					//// 反复连，反复发送，接收，考验服务器耐力
					//g_pMSWInSock2Fun->ConnectEx(pMyOl->m_skConnect
					//	, (SOCKADDR*)&pMyOl->m_saRemote
					//	, pMyOl->m_iRemoteLen
					//	, nullptr
					//	, 0
					//	, &pMyOl->m_dwTrasBytes
					//	, (LPOVERLAPPED)pMyOl);

					continue;
				}
                else
                {
                    GRS_PRINTF(_T("[%8u]: IOCPThread: GetQueuedCompletionStatus 调用失败,错误码: 0x%08x 内部错误码[0x%08x]\n")
                        , GetCurrentThreadId()
                        , GetLastError()
                        , lpOverlapped ? lpOverlapped->Internal : WSAGetLastError());
                    break;
                } 
            }

            switch (pMyOl->m_lOperation)
            {
            case FD_CONNECT:
            {
                GRS_PRINTF(_T("[%8u]: 完成操作\"ConnectEx\"，远端IP[%s]，开始发送数据：\n")
                    , GetCurrentThreadId()
                    , pMyOl->m_pszAddrRemot);

                int nRet = ::setsockopt(
                    pMyOl->m_skConnect,
                    SOL_SOCKET,
                    SO_UPDATE_CONNECT_CONTEXT,
                    nullptr,
                    0
                );

                int iBufLen = 0;
                //关闭套接字上的发送缓冲，这样可以提高性能
                ::setsockopt(pMyOl->m_skConnect,SOL_SOCKET,SO_SNDBUF,(const char*)&iBufLen,sizeof(int));
                ::setsockopt(pMyOl->m_skConnect,SOL_SOCKET,SO_RCVBUF,(const char*)&iBufLen,sizeof(int));

                //强制发送延时算法关闭,直接发送到网络上去
                DWORD dwNo  = 0;
                ::setsockopt(pMyOl->m_skConnect,IPPROTO_TCP,TCP_NODELAY,(char*)&dwNo,sizeof(DWORD));

                BOOL bDontLinger = FALSE; 
                ::setsockopt(pMyOl->m_skConnect,SOL_SOCKET,SO_DONTLINGER,(const char*)&bDontLinger,sizeof(BOOL));

                linger sLinger = {};
                sLinger.l_onoff = 1;
                sLinger.l_linger = 0;
                ::setsockopt(pMyOl->m_skConnect,SOL_SOCKET,SO_LINGER,(const char*)&sLinger,sizeof(linger));

                pMyOl->m_lOperation = FD_WRITE;
                pMyOl->m_dwFlags = 0;
                // 注意直接把消息缓冲发出去，这里是只读的，所以共用一块静态缓冲是没有问题的
                pMyOl->m_wsaBuf.buf = (CHAR*)pszSendMsg;
                pMyOl->m_wsaBuf.len = dwMsgLen;

                ::WSASend(pMyOl->m_skConnect
                    , &pMyOl->m_wsaBuf
                    , 1
                    , &pMyOl->m_dwTrasBytes
                    , pMyOl->m_dwFlags
                    , (LPOVERLAPPED)&pMyOl->m_wsaOL
                    , nullptr);

            }
            break;
            case FD_WRITE:
            {
                GRS_PRINTF(_T("[%8u]: 完成操作\"WSASend\",缓冲(0x%08x)长度(%u bytes),实际传输( %u : %u )\n")
                    , GetCurrentThreadId()
                    , pMyOl->m_wsaBuf.buf
                    , pMyOl->m_wsaBuf.len
                    , dwBytesTransfered
                    , pMyOl->m_dwTrasBytes);

                // 这个清0操作不是必须的，但是为了验证我们确实是从服务端接收的返回的数据，所以清一下
                ZeroMemory(pMyOl->m_pBuf, pMyOl->m_szBufLen);

                pMyOl->m_dwFlags = 0;
                pMyOl->m_lOperation = FD_READ;
                pMyOl->m_wsaBuf.buf = (CHAR*)pMyOl->m_pBuf;
                pMyOl->m_wsaBuf.len = (ULONG)pMyOl->m_szBufLen;

                ::WSARecv(pMyOl->m_skConnect
                    , &pMyOl->m_wsaBuf
                    , 1
                    , &pMyOl->m_dwTrasBytes
                    , &pMyOl->m_dwFlags
                    , (LPOVERLAPPED)&pMyOl->m_wsaOL
                    , nullptr);
            }
            break;
            case FD_READ:
            {
                GRS_PRINTF(_T("[%8u]: 完成操作\"WSARecv\",缓冲(0x%08x)长度(%u bytes),实际传输( %u : %u )\nECHO: %s\n")
                    , GetCurrentThreadId()
                    , pMyOl->m_wsaBuf.buf
                    , pMyOl->m_wsaBuf.len
                    , dwBytesTransfered
                    , pMyOl->m_dwTrasBytes
                    , pMyOl->m_wsaBuf.buf);

                pMyOl->m_lOperation = FD_CLOSE;
                pMyOl->m_dwFlags = 0;
                //回收SOCKET
                ::shutdown(pMyOl->m_skConnect, SD_BOTH);
                g_pMSWInSock2Fun->DisconnectEx(pMyOl->m_skConnect, (LPOVERLAPPED)pMyOl, TF_REUSE_SOCKET, 0);

            }
            break;
            case FD_CLOSE:
            {
                if ( INVALID_SOCKET == pMyOl->m_skConnect )
                {
                    bLoop = FALSE;//退出循环
                }
                else
                {
                    GRS_PRINTF(_T("[%8u]: 完成操作\"DisconnectEx\",回收SOCKET[0x%08x]成功，重新发起连接，远端IP[%s]。\n")
                        , GetCurrentThreadId()
                        , pMyOl->m_skConnect
                        , pMyOl->m_pszAddrRemot);

                    sockaddr_in stLocalIP = {};
                    stLocalIP.sin_family = AF_INET;
                    stLocalIP.sin_addr.s_addr = INADDR_ANY; // 本地绑定的地址放在默认的 0.0.0.0 这样可以通过所有可能的路由途径链接到服务端
                    stLocalIP.sin_port = htons((short)0);	// 使用0让系统自动分配

                    //允许地址重用
                    const int on = 1;
                    //::setsockopt(pMyOl->m_skConnect, SOL_SOCKET, SO_REUSEADDR, (char*)&on, sizeof(on));
                    ::bind(pMyOl->m_skConnect, (LPSOCKADDR)&stLocalIP, sizeof(SOCKADDR_IN));

                    ::getsockname(pMyOl->m_skConnect, (SOCKADDR*)&pMyOl->m_saLocal, &pMyOl->m_iLocalLen);

                    RtlIpv4AddressToStringEx(&pMyOl->m_saLocal.sin_addr
                        , pMyOl->m_saLocal.sin_port
                        , pMyOl->m_pszAddrLocal
                        , &pMyOl->m_ulAddrLocalLen);

                    GRS_PRINTF(_T("[%8u]: SOCKET[0x%08x]绑定新地址为[%s]。\n")
                        , GetCurrentThreadId()
                        , pMyOl->m_skConnect
                        , pMyOl->m_pszAddrLocal);

                    pMyOl->m_dwFlags = 0;
                    pMyOl->m_lOperation = FD_CONNECT;
                    
                    // 回收成功,重新丢入连接池
                    // 反复连，反复发送，接收，考验服务器耐力
                    g_pMSWInSock2Fun->ConnectEx(pMyOl->m_skConnect
                        , (SOCKADDR*)&pMyOl->m_saRemote
                        , pMyOl->m_iRemoteLen
                        , nullptr
                        , 0
                        , &pMyOl->m_dwTrasBytes
                        , (LPOVERLAPPED)pMyOl);
                }
            }
            break;
            default:
            {
                bLoop = FALSE;
            }
            break;
            }
        }
    }
    catch (CAtlException& e)
    {//发生了COM异常
        e;
        iRet = e.m_hr;
    }
    catch (...)
    {
        iRet = -1;
    }
    GRS_PRINTF(_T("[%8u]: IOCP线程退出[Code: 0x%08x]。\n"), GetCurrentThreadId(), iRet);
    return iRet;
}
