
#include <tchar.h>
#define WIN32_LEAN_AND_MEAN	
#include <windows.h>
#include <tchar.h>
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
#define GRS_ALLOC(sz)		::HeapAlloc(GetProcessHeap(),0,(sz))
#define GRS_CALLOC(sz)		::HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,(sz))
#define GRS_CREALLOC(p,sz)	::HeapReAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,(p),(sz))
#define GRS_SAFEFREE(p)		if( nullptr != (p) ){ ::HeapFree( ::GetProcessHeap(),0,(p) ); (p) = nullptr; }

// 启动线程的宏定义
#define GRS_BEGINTHREAD(Fun,Param) (HANDLE)_beginthreadex(nullptr,0,(_beginthreadex_proc_type)(Fun),(Param),0,nullptr)

// 一些默认参数，这些参数可以定义到配置文件中去，比如INI、XML、Lua等
#define GRS_SERVER_IP                   _T("0.0.0.0")  // 默认监听IP地址，注意多网卡，多IP系统，需要内外网隔离时，需要明确指定监听在哪个IP上
#define GRS_SERVER_PORT                 8080    // 监听端口
#define GRS_DATA_BUFSIZE_DEFAULT        4096    // 默认数据缓冲大小
#define GRS_DATA_BUF_GROW_SIZE          4096    // 数据缓冲增长大小
#define GRS_THREAD_POOL_THREAD_COUNT    0       // 默认启动的线程数量，当为0时，自动根据系统逻辑内核数量创建等量的线程
#define GRS_MAX_LISTEN_SOCKET           5       // 最大同时侦听的SOCKET数，实质是并行的Accept数量，循环使用就可以完成高并发响应

// 以下是自定义Overlapped结构的相关宏和结构体定义
// 注意保持其内部数据的原子性，不要牵扯全局变量或跨域跨线程的定义
// 否则必须要进行低效的跨线程同步访问，就失去了使用多线程SOCKET池的意义
#define GRS_ADDR_STR_LEN            36
#define GRS_WSABUF_COUNT_DEFAULT    1

struct ST_GRS_MY_WSAOVERLAPPED
{
    WSAOVERLAPPED m_wsaOL;
    SOCKET        m_skLocal;        // 监听套接字句柄
    SOCKET        m_skRemote;       // 投递操作的SOCKET句柄 也就是链接远端的SOCKET

    ULONG         m_ulAddrLocalLen;
    ULONG         m_ulAddrRemotLen;
    TCHAR         m_pszAddrLocal[GRS_ADDR_STR_LEN];
    TCHAR         m_pszAddrRemot[GRS_ADDR_STR_LEN];
                                                    
    INT           m_iLocalLen;
    SOCKADDR_IN*  m_psaLocal;
    INT           m_iRemoteLen;
    SOCKADDR_IN*  m_psaRemote;
        
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
        // 命令行窗口最大化
        ::ShowWindow(GetConsoleWindow(), SW_MAXIMIZE);

        GRS_USEPRINTF();
        
        DWORD   dwProcessorCnt  = GRS_THREAD_POOL_THREAD_COUNT;
        int     iMaxAcceptEx    = GRS_MAX_LISTEN_SOCKET;
        SIZE_T  szDefaultBufLen = GRS_DATA_BUFSIZE_DEFAULT;
        SOCKET  skListen        = INVALID_SOCKET;
        SOCKET  skAccept        = INVALID_SOCKET;
        ST_GRS_MY_WSAOVERLAPPED* pOLAcceptEx = nullptr;

        if( 0 == dwProcessorCnt )
        {
            SYSTEM_INFO si = {};
            ::GetSystemInfo(&si);
            dwProcessorCnt = si.dwNumberOfProcessors;
        }

        g_pWinSock2Fun = CGRSWinSock2Fun::GetInstance();

        // 创建IOCP内核对象,允许最大并发CPU个数个线程
        g_hIOCP = ::CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, dwProcessorCnt);
        if ( nullptr == g_hIOCP )
        {
            GRS_PRINTF(_T("[%8u]: 完成端口创建失败，程序将退出！\n"), GetCurrentThreadId());
            AtlThrowLastWin32();
        }

        // 创建CPU个数个线程
        for ( DWORD i = 0; i < dwProcessorCnt; i++ )
        {
            g_arThread.Add( GRS_BEGINTHREAD(GRSIOCPThread, g_hIOCP) );
        }

        GRS_PRINTF(_T("[%8u]: [%u]个线程被启动。\n"), GetCurrentThreadId(), g_arThread.GetCount());

        // 创建监听（Listen）句柄
        skListen = ::WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, WSA_FLAG_OVERLAPPED);

        // 将SOCKET句柄与完成端口对象绑定
        // 注意监听的套接字一定要先和IOCP绑定,否则AcceptEx就无法利用IOCP处理
        ::CreateIoCompletionPort((HANDLE)skListen, g_hIOCP, 0, 0);

        sockaddr_in service;
        service.sin_family = AF_INET;
        service.sin_port = htons(GRS_SERVER_PORT); // 注意互联网上是大端序

        LPCTSTR pszTerminator = _T("");
        // 默认是绑到本地地址（0.0.0.0) 在多网口多IP系统中，这相当于在所有的IP上都监听
        ::RtlIpv4StringToAddress(GRS_SERVER_IP, TRUE, &pszTerminator, &service.sin_addr);

        //service.sin_addr.s_addr = INADDR_ANY;      

        if ( 0 != ::bind(skListen, (SOCKADDR*)&service, sizeof(SOCKADDR)) )
        {
            GRS_PRINTF( _T("[%8u]: 绑定到IP[%s:%d]失败，错误码[0x%08X],程序将退出！\n")
                , GetCurrentThreadId()
                , GRS_SERVER_IP
                , GRS_SERVER_PORT
                , ::WSAGetLastError());
            AtlThrowLastWin32();
        }

        // 注意这里指定了最大可能的侦听队列大小，实际值由系统内部确定
        if (0 != ::listen(skListen, SOMAXCONN))
        {
            GRS_PRINTF( _T("[%8u]: 启动监听失败，错误码[0x%08X],程序将退出！\n")
                , GetCurrentThreadId()
                , ::WSAGetLastError());
            AtlThrowLastWin32();
        }
        
        GRS_PRINTF( _T("[%8u]: Server IP[%s:%d] Start Listening...\n\n"), GetCurrentThreadId(), GRS_SERVER_IP, GRS_SERVER_PORT );

        //发起AcceptEx调用
        for ( int i = 0; i < iMaxAcceptEx; i++ )
        {
            skAccept = ::WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, WSA_FLAG_OVERLAPPED);
            g_arSocket.Add(skAccept);

            pOLAcceptEx = (ST_GRS_MY_WSAOVERLAPPED*)GRS_CALLOC(sizeof(ST_GRS_MY_WSAOVERLAPPED));
            ATLASSERT(nullptr != pOLAcceptEx); // 正式代码中这里要判断并正确终止

            g_arOverlapped.Add(pOLAcceptEx);

            pOLAcceptEx->m_ulAddrLocalLen   = GRS_ADDR_STR_LEN;
            pOLAcceptEx->m_ulAddrRemotLen   = GRS_ADDR_STR_LEN;
            pOLAcceptEx->m_iLocalLen        = sizeof(SOCKADDR_IN);
            pOLAcceptEx->m_psaLocal         = nullptr;
            pOLAcceptEx->m_iRemoteLen       = sizeof(SOCKADDR_IN);
            pOLAcceptEx->m_psaRemote        = nullptr;

            pOLAcceptEx->m_skLocal          = skListen;
            pOLAcceptEx->m_skRemote         = skAccept;
            pOLAcceptEx->m_lOperation       = FD_ACCEPT;
            pOLAcceptEx->m_szBufLen         = max(szDefaultBufLen, 2 * (sizeof(SOCKADDR_IN) + 16));
            pOLAcceptEx->m_pBuf             = GRS_CALLOC( pOLAcceptEx->m_szBufLen );            

            //将SOCKET句柄与完成端口对象绑定
            ::CreateIoCompletionPort((HANDLE)skAccept, g_hIOCP, 0, 0);

            // 注意用0缓冲长度调用AcceptEx，这样防止恶意链接不发数据导致AcceptEx一直无法返回，而成为死连接
            if (!g_pWinSock2Fun->AcceptEx(skListen
                , skAccept
                , pOLAcceptEx->m_pBuf
                , 0
                , sizeof(SOCKADDR_IN) + 16
                , sizeof(SOCKADDR_IN) + 16
                , &pOLAcceptEx->m_dwTrasBytes
                , (LPOVERLAPPED)&pOLAcceptEx->m_wsaOL))
            {
                int iError = WSAGetLastError();
                if (ERROR_IO_PENDING != iError && WSAECONNRESET != iError)
                {
                    if ( INVALID_SOCKET != skAccept )
                    {
                        ::closesocket(skAccept);
                        skAccept = INVALID_SOCKET;
                    }

                    GRS_SAFEFREE(pOLAcceptEx->m_pBuf);
                    GRS_SAFEFREE(pOLAcceptEx);
                    
                    // 不从数组中删除，只是置为无效值
                    g_arSocket.SetAt(i, INVALID_SOCKET);
                    g_arOverlapped.SetAt(i, nullptr);

                    GRS_PRINTF(_T("[%8u]: 调用AcceptEx失败,错误码:%d\n"), GetCurrentThreadId(), iError);
                    continue;
                }
            }

            GRS_PRINTF(_T("[%8u]: (%d)SOCKERT[0x%08X] AcceptEx...\n"), GetCurrentThreadId(), i , skAccept);
        }

        GRS_PRINTF(_T("[%8u]: 主线程进入等待状态，按\'q\'键退出。\n"), GetCurrentThreadId());
        //主线程进入等待状态
        INPUT_RECORD sinfo = {};
        DWORD recnum = 0;
        HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
        while ( ReadConsoleInput(hIn, &sinfo, 1, &recnum) )
        {
            if ( sinfo.EventType != KEY_EVENT )
            {
                continue;//无视其他类型输入
            }
            //判断按键状态(以防按键被触发两次)
            if ( sinfo.Event.KeyEvent.uChar.UnicodeChar == L'q')
            {
                break;
            }
        }
     
        GRS_PRINTF(_T("[%8u]: 主线程接到退出消息......\n"), GetCurrentThreadId());
        //向IOCP线程池发送退出消息 利用标志FD_CLOSE标志
        ST_GRS_MY_WSAOVERLAPPED     stQuitMsgOL = {};
        stQuitMsgOL.m_skRemote      = INVALID_SOCKET;
        stQuitMsgOL.m_lOperation    = FD_CLOSE;

        for (DWORD i = 0; i < (DWORD)g_arThread.GetCount(); i++)
        {
            ::PostQueuedCompletionStatus(g_hIOCP, 0, skListen, (LPOVERLAPPED)&stQuitMsgOL);
        }
        ::WaitForMultipleObjects((DWORD)g_arThread.GetCount(), g_arThread.GetData(), TRUE, INFINITE);

        for (DWORD i = 0; i < (DWORD)g_arThread.GetCount(); i++)
        {
            ::CloseHandle(g_arThread[i]);
        }

        g_arThread.RemoveAll();

        ::CloseHandle(g_hIOCP);

        //释放SOCKET及ST_GRS_MY_WSAOVERLAPPED资源
        if (INVALID_SOCKET != skListen)
        {
            closesocket(skListen);
        }

        for (int i = 0; i < (int)g_arSocket.GetCount(); i++)
        {
            if (INVALID_SOCKET != g_arSocket[i])
            {
                closesocket(g_arSocket[i]);
            }   
        }

        for (SIZE_T i = 0; i < g_arOverlapped.GetCount(); i ++ )
        {
            GRS_SAFEFREE(g_arOverlapped[i]->m_pBuf);
            GRS_SAFEFREE(g_arOverlapped[i]);
        }

        g_arOverlapped.RemoveAll();
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
    //----------------------------------------------------------------------------------
    // 注意代码中有很多 GetCurrentThreadId() 的调用，这看上去好像不必要，完全可以
    // 用变量来存储这个值，但是不要忘了这是一个多线程的线程函数，每次被调用时都有可能
    // 是不同的线程，所以每次需要知道是哪个线程时必须要获取这个线程函数即时的线程ID
    // 保持在局部变量中的ID值可能并不是真实的当前线程的ID
    // 当然现代的Windows线程调度算法已经充分考虑了线程的亲缘性，基本上不会出现同
    // 一个线程函数的实例或者说同一个线程上下文环境被调度到不同的CPU逻辑核上去的
    // 情况，但是这个不是绝对可靠的特性
    // 所以为了准确知道是哪个线程在调用当前实例，就必须时刻调用 GetCurrentThreadId() 来感知
    //----------------------------------------------------------------------------------
    unsigned int nRet = 0;
    GRS_USEPRINTF();
	try
	{
        HANDLE                      hIOCP               = (HANDLE)lpParameter;
        DWORD                       dwBytesTransfered   = 0;
        ULONG_PTR                   pKey                = 0;
        OVERLAPPED*                 lpOverlapped        = nullptr;
        ST_GRS_MY_WSAOVERLAPPED*    pstCurrentTransOL   = nullptr;

        BOOL                        bRet                = TRUE;
        BOOL                        bLoop               = TRUE;
        
        SIZE_T                      szBufGrowLen        = GRS_DATA_BUF_GROW_SIZE;

        ATLASSERT(nullptr != hIOCP && hIOCP == g_hIOCP);

        while (bLoop)
        {
            bRet = ::GetQueuedCompletionStatus(hIOCP, &dwBytesTransfered, (PULONG_PTR)&pKey, &lpOverlapped, INFINITE);
            pstCurrentTransOL = CONTAINING_RECORD(lpOverlapped, ST_GRS_MY_WSAOVERLAPPED, m_wsaOL);

            if ( FALSE == bRet )
            {
                // 这里实际中还需要进一步判断 pKey 和 lpOverlapped 同为 nullptr 如果是可以确定是退出消息
                // 否则就是个出错的通知 需要用 DisConnectEX 回收 Socket

                GRS_PRINTF(_T("[%8u]: GRSIOCPThread: GetQueuedCompletionStatus 调用失败,错误码:[0x%08x] 内部错误码[0x%08x]\n")
                    , GetCurrentThreadId()
                    , GetLastError()
                    , lpOverlapped ? lpOverlapped->Internal : WSAGetLastError() );

                AtlThrowLastWin32();
            }

            switch ( pstCurrentTransOL->m_lOperation )
            {// 下面的操作相当于一个状态机
            case FD_ACCEPT:
            {
                GRS_PRINTF(_T("[%8u]: 完成操作\"AcceptEx\",缓冲(0x%08x)长度(%u bytes),实际传输( %u : %u )\n")
                    , GetCurrentThreadId()
                    , pstCurrentTransOL->m_pBuf
                    , pstCurrentTransOL->m_szBufLen
                    , dwBytesTransfered
                    , pstCurrentTransOL->m_dwTrasBytes);

                pstCurrentTransOL->m_iLocalLen = sizeof(SOCKADDR_IN);
                pstCurrentTransOL->m_iRemoteLen = sizeof(SOCKADDR_IN);

                g_pWinSock2Fun->GetAcceptExSockaddrs(
                    pstCurrentTransOL->m_pBuf
                    , 0
                    , sizeof(SOCKADDR_IN) + 16
                    , sizeof(SOCKADDR_IN) + 16
                    , (SOCKADDR**)&pstCurrentTransOL->m_psaLocal
                    , &pstCurrentTransOL->m_iLocalLen
                    , (SOCKADDR**)&pstCurrentTransOL->m_psaRemote
                    , &pstCurrentTransOL->m_iRemoteLen);

                pstCurrentTransOL->m_ulAddrLocalLen = GRS_ADDR_STR_LEN;
                pstCurrentTransOL->m_ulAddrRemotLen = GRS_ADDR_STR_LEN;

                RtlIpv4AddressToStringEx(&pstCurrentTransOL->m_psaLocal->sin_addr
                    , pstCurrentTransOL->m_psaLocal->sin_port
                    , pstCurrentTransOL->m_pszAddrLocal
                    , &pstCurrentTransOL->m_ulAddrLocalLen);

                RtlIpv4AddressToStringEx(&pstCurrentTransOL->m_psaRemote->sin_addr
                    , pstCurrentTransOL->m_psaRemote->sin_port
                    , pstCurrentTransOL->m_pszAddrRemot
                    , &pstCurrentTransOL->m_ulAddrRemotLen);

                GRS_PRINTF(_T("[%8u]: 远端IP[%s]连接进入,本地IP[%s]\n")
                    , GetCurrentThreadId()
                    , pstCurrentTransOL->m_pszAddrRemot
                    , pstCurrentTransOL->m_pszAddrLocal);

                //GRS_SAFEFREE(pstCurrentTransOL->m_pBuf);

                int nRet = ::setsockopt(
                    pstCurrentTransOL->m_skRemote,
                    SOL_SOCKET,
                    SO_UPDATE_ACCEPT_CONTEXT,
                    (char*)&pstCurrentTransOL->m_skLocal,
                    sizeof(SOCKET)
                );

                int iBufLen = 0;
                //关闭套接字上的发送缓冲，这样可以提高性能
                ::setsockopt(pstCurrentTransOL->m_skRemote, SOL_SOCKET, SO_SNDBUF, (const char*)&iBufLen, sizeof(int));
                ::setsockopt(pstCurrentTransOL->m_skRemote, SOL_SOCKET, SO_RCVBUF, (const char*)&iBufLen, sizeof(int));

                //强制发送延时算法关闭,直接发送到网络上去
                DWORD dwNo = 0;
                ::setsockopt(pstCurrentTransOL->m_skRemote, IPPROTO_TCP, TCP_NODELAY, (char*)&dwNo, sizeof(DWORD));

                BOOL bDontLinger = FALSE;
                ::setsockopt(pstCurrentTransOL->m_skRemote, SOL_SOCKET, SO_DONTLINGER, (const char*)&bDontLinger, sizeof(BOOL));

                linger sLinger = {};
                sLinger.l_onoff = 1;
                sLinger.l_linger = 0;
                ::setsockopt(pstCurrentTransOL->m_skRemote, SOL_SOCKET, SO_LINGER, (const char*)&sLinger, sizeof(linger));

                pstCurrentTransOL->m_wsaBuf.buf = (CHAR*)pstCurrentTransOL->m_pBuf;
                pstCurrentTransOL->m_wsaBuf.len = (ULONG)pstCurrentTransOL->m_szBufLen;

                // 将下列重要信息通过扩展OVERLAPPED的结构带到回调过程中去
                // 注意这个例子只是一个Echo服务器，所以当是Accept完成后，就调用WSAResv迁移到Read状态去
                pstCurrentTransOL->m_lOperation = FD_READ;               
                pstCurrentTransOL->m_dwTrasBytes = 0;
                if (WSARecv(pstCurrentTransOL->m_skRemote
                    , &pstCurrentTransOL->m_wsaBuf
                    , 1
                    , &pstCurrentTransOL->m_dwTrasBytes
                    , &pstCurrentTransOL->m_dwFlags
                    , (WSAOVERLAPPED*)pstCurrentTransOL
                    , nullptr) == SOCKET_ERROR)
                {
                    int iErrorCode = WSAGetLastError();
                    if ( iErrorCode != WSA_IO_PENDING )
                    {
                        GRS_PRINTF(_T("[%8u]: WSARecv发生错误[0x%08x]\n"), GetCurrentThreadId(), iErrorCode);
                    }
                }
            }
            break;
            case FD_WRITE:
            {
                GRS_PRINTF(_T("[%8u]: 完成操作\"WSASend\",远端IP[%s],缓冲(0x%08x)长度(%u Bytes),实际传输( %u : %u )\n")
                    , GetCurrentThreadId()
                    , pstCurrentTransOL->m_pszAddrRemot
                    , pstCurrentTransOL->m_pBuf
                    , pstCurrentTransOL->m_szBufLen 
                    , dwBytesTransfered
                    , pstCurrentTransOL->m_dwTrasBytes);

                //shutdown(pstCurrentTransOL->m_skRemote, SD_BOTH);

                pstCurrentTransOL->m_lOperation = FD_CLOSE;
                pstCurrentTransOL->m_dwTrasBytes = 0;

                //回收SOCKET
                g_pWinSock2Fun->DisconnectEx(pstCurrentTransOL->m_skRemote, (LPOVERLAPPED)pstCurrentTransOL, TF_REUSE_SOCKET, 0);
            }
            break;
            case FD_READ:
            {
                GRS_PRINTF(_T("[%8u]: 完成操作\"WSARecv\",远端IP[%s],缓冲(0x%08x)长度(%u Bytes),实际接收( %u : %u )，判断数据是否接收完成：\n")
                    , GetCurrentThreadId()
                    , pstCurrentTransOL->m_pszAddrRemot
                    , pstCurrentTransOL->m_pBuf
                    , pstCurrentTransOL->m_szBufLen
                    , dwBytesTransfered
                    , pstCurrentTransOL->m_dwTrasBytes);

                if ( pstCurrentTransOL->m_dwTrasBytes < pstCurrentTransOL->m_wsaBuf.len )
                {// 实际接收的字节数小于缓冲长度，说明接收完成，否则再放一个接收
                    pstCurrentTransOL->m_wsaBuf.buf = (CHAR*) pstCurrentTransOL->m_pBuf;
                    pstCurrentTransOL->m_wsaBuf.len = (ULONG)( pstCurrentTransOL->m_szBufLen <= szBufGrowLen 
                        ? pstCurrentTransOL->m_dwTrasBytes 
                        : pstCurrentTransOL->m_szBufLen - szBufGrowLen + pstCurrentTransOL->m_dwTrasBytes );

                    pstCurrentTransOL->m_lOperation = FD_WRITE;
                    pstCurrentTransOL->m_dwFlags = 0;
                    pstCurrentTransOL->m_dwTrasBytes = 0;

                    GRS_PRINTF(_T("[%8u]: 远端IP[%s]的数据[%u Bytes]已经接收完成，反向发送回去！\n")
                        , GetCurrentThreadId()
                        , pstCurrentTransOL->m_pszAddrRemot
                        , pstCurrentTransOL->m_wsaBuf.len);

                    if (SOCKET_ERROR == WSASend(
                        pstCurrentTransOL->m_skRemote
                        , &pstCurrentTransOL->m_wsaBuf
                        , 1
                        , &pstCurrentTransOL->m_dwTrasBytes
                        , pstCurrentTransOL->m_dwFlags
                        , (LPWSAOVERLAPPED)pstCurrentTransOL
                        , nullptr))
                    {
                        int iErrorCode = WSAGetLastError();
                        if ( iErrorCode != WSA_IO_PENDING )
                        {
                            GRS_PRINTF(_T("[%8u]: WSASend发生错误[0x%08x]\n"), GetCurrentThreadId(), iErrorCode);
                            // shutdown(pstCurrentTransOL->m_skRemote, SD_BOTH);
                            pstCurrentTransOL->m_lOperation = FD_CLOSE;
                            pstCurrentTransOL->m_dwFlags = 0;
                            pstCurrentTransOL->m_dwTrasBytes = 0;
                            g_pWinSock2Fun->DisconnectEx(pstCurrentTransOL->m_skRemote
                                , (LPOVERLAPPED)pstCurrentTransOL
                                , TF_REUSE_SOCKET
                                , 0);
                            break;
                        }
                    }            
                }
                else
                {
                    SIZE_T szOldBufLen = pstCurrentTransOL->m_szBufLen;
                    pstCurrentTransOL->m_szBufLen += szBufGrowLen;                    
                    pstCurrentTransOL->m_pBuf = GRS_CREALLOC(pstCurrentTransOL->m_pBuf, pstCurrentTransOL->m_szBufLen);

                    // 注意正式代码中不但要判断内存分配情况，还要判断缓冲区长度不要超过某个设定的阈值，防止恶意传输代码
                    // 或者当需要传输较大长度的内容，如文件时，考虑将之前的内容直接追加到指定的文件中，然后重用同一块缓冲
                    // 我们这里只是判断下内存还能不能分配
                    ATLASSERT( nullptr != pstCurrentTransOL->m_pBuf );

                    pstCurrentTransOL->m_wsaBuf.buf = (CHAR*)pstCurrentTransOL->m_pBuf + szOldBufLen;
                    pstCurrentTransOL->m_wsaBuf.len = (ULONG)szBufGrowLen;
                    // 将下列重要信息通过扩展OVERLAPPED的结构带到回调过程中去
                    // 注意这个例子只是一个Echo服务器，所以当是Accept完成后，就调用WSAResv迁移到Read状态去
                    pstCurrentTransOL->m_lOperation = FD_READ;
                    pstCurrentTransOL->m_dwFlags = 0;
                    pstCurrentTransOL->m_dwTrasBytes = 0;

                    GRS_PRINTF(_T("[%8u]: 远端IP[%s]的数据未接收完成，已接收[%u Bytes]，分配[%u Bytes]继续进行接收！\n")
                        , GetCurrentThreadId()
                        , pstCurrentTransOL->m_pszAddrRemot
                        , szOldBufLen
                        , pstCurrentTransOL->m_wsaBuf.len);

                    if (WSARecv(pstCurrentTransOL->m_skRemote
                        , &pstCurrentTransOL->m_wsaBuf
                        , 1
                        , &pstCurrentTransOL->m_dwTrasBytes
                        , &pstCurrentTransOL->m_dwFlags
                        , (WSAOVERLAPPED*)pstCurrentTransOL
                        , nullptr) == SOCKET_ERROR)
                    {
                        int iErrorCode = WSAGetLastError();
                        if (iErrorCode != WSA_IO_PENDING)
                        {
                            GRS_PRINTF(_T("[%8u]: WSARecv发生错误[0x%08x]\n"), GetCurrentThreadId(), iErrorCode);
                        }
                    }
                }
            }
            break;
            case FD_CLOSE:
            {
                if ( INVALID_SOCKET == pstCurrentTransOL->m_skRemote )
                {
                    GRS_PRINTF(_T("[%8u]: IOCP线程得到退出通知,IOCP线程退出\n"),
                        GetCurrentThreadId());

                    bLoop = FALSE;//退出循环
                }
                else
                {
                    GRS_PRINTF(_T("[%8u]: 完成操作\"DisconnectEx\",缓冲(0x%08x)长度(%u bytes),回收SOCKET[0x%08x]成功,重新AcceptEx......\n")
                        , GetCurrentThreadId()
                        , pstCurrentTransOL->m_pBuf
                        , pstCurrentTransOL->m_szBufLen 
                        , pstCurrentTransOL->m_skRemote);

                    // 缓冲恢复默认大小
                    if( pstCurrentTransOL->m_szBufLen > GRS_DATA_BUFSIZE_DEFAULT )
                    {
                        pstCurrentTransOL->m_szBufLen = GRS_DATA_BUFSIZE_DEFAULT;
                        pstCurrentTransOL->m_pBuf = GRS_CREALLOC(pstCurrentTransOL->m_pBuf, pstCurrentTransOL->m_szBufLen);
                    }
 
                    pstCurrentTransOL->m_lOperation = FD_ACCEPT;
                    pstCurrentTransOL->m_dwFlags = 0;
                    pstCurrentTransOL->m_dwTrasBytes = 0;

                    //回收成功,重新丢入连接池
                    g_pWinSock2Fun->AcceptEx(pstCurrentTransOL->m_skLocal
                        , pstCurrentTransOL->m_skRemote
                        , pstCurrentTransOL->m_pBuf
                        , 0
                        , sizeof(SOCKADDR_IN) + 16
                        , sizeof(SOCKADDR_IN) + 16
                        , &pstCurrentTransOL->m_dwFlags
                        , (LPOVERLAPPED)pstCurrentTransOL);
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
        nRet = e.m_hr;
	}
	catch (...)
	{
        nRet = -1;
	}
    GRS_PRINTF(_T("[%8u]: IOCP线程退出[Code: 0x%08x]。\n"), GetCurrentThreadId(), nRet);

    return nRet;
}
