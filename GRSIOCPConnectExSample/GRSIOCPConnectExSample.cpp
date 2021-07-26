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

// ��������������ĺ궨��
#define GRS_USEPRINTF() TCHAR pOutBufT[1024] = {};CHAR pOutBufA[1024] = {};
#define GRS_PRINTF(...) \
    StringCchPrintf(pOutBufT,1024,__VA_ARGS__);\
    WriteConsole(GetStdHandle(STD_OUTPUT_HANDLE),pOutBufT,lstrlen(pOutBufT),nullptr,nullptr);
#define GRS_PRINTFA(...) \
    StringCchPrintfA(pOutBufA,1024,__VA_ARGS__);\
    WriteConsoleA(GetStdHandle(STD_OUTPUT_HANDLE),pOutBufA,lstrlenA(pOutBufA),nullptr,nullptr);

// �ڴ����ĺ궨��
#define GRS_ALLOC(sz)		HeapAlloc(GetProcessHeap(),0,sz)
#define GRS_CALLOC(sz)		HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sz)
#define GRS_CREALLOC(p,sz)	HeapReAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,p,sz)
#define GRS_SAFEFREE(p)		if(nullptr != p){HeapFree(GetProcessHeap(),0,p);p=nullptr;}

// �����̵߳ĺ궨��
#define GRS_BEGINTHREAD(Fun,Param) (HANDLE)_beginthreadex(nullptr,0,(_beginthreadex_proc_type)(Fun),(Param),0,nullptr)

// �Զ���Sleep ʱ�侫�ȸ���
#define GRS_SLEEP(dwMilliseconds)  WaitForSingleObject(GetCurrentThread(),dwMilliseconds)

// һЩĬ�ϲ�������Щ�������Զ��嵽�����ļ���ȥ������INI��XML��Lua��
#define GRS_SERVER_IP                   _T("127.0.0.1")  // ��������IP
#define GRS_SERVER_PORT                 8080    // �������Ķ˿�
#define GRS_DATA_BUFSIZE_DEFAULT        4096    // Ĭ�����ݻ����С
#define GRS_DATA_BUF_GROW_SIZE          4096    // ���ݻ���������С
#define GRS_THREAD_POOL_THREAD_COUNT    0       // Ĭ���������߳���������Ϊ0ʱ���Զ�����ϵͳ�߼��ں����������������߳�
#define GRS_MAX_CONNECT_SOCKET          1       // ���ͬʱ������SOCKET����ʵ���ǲ��е�Accept������ѭ��ʹ�þͿ�����ɸ߲�����Ӧ

// �������Զ���Overlapped�ṹ����غ�ͽṹ�嶨��
// ע�Ᵽ�����ڲ����ݵ�ԭ���ԣ���Ҫǣ��ȫ�ֱ����������̵߳Ķ���
// �������Ҫ���е�Ч�Ŀ��߳�ͬ�����ʣ���ʧȥ��ʹ�ö��߳�SOCKET�ص�����
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

    LONG          m_lOperation;     // Ͷ�ݵĲ�������(FD_READ/FD_WRITE��)

    DWORD		  m_dwTrasBytes;    // ΪWSASent��WSARecv׼���Ĳ���
    DWORD         m_dwFlags;        // ΪWSARecv׼����

    WSABUF        m_wsaBuf;         // WinSock2�����������еĴ��仺��ṹ�壬��Ҫ��CHAR*�����Ի󣬻����п��Է��������ݣ�������˵ֻ�ܴ�ASSIC�ַ�
    SIZE_T        m_szBufLen;       // ���ݻ��峤��
    PVOID         m_pBuf;           // Ͷ�ݲ���ʱ�����ݻ���
};

typedef CAtlArray<HANDLE> CGRSHandleArray;
typedef CAtlArray<SOCKET> CGRSSocketArray;
typedef CAtlArray<ST_GRS_MY_WSAOVERLAPPED*> CGRSOverlappedArray;

//IOCP�̳߳��̺߳���
unsigned int __stdcall GRSIOCPThread(void* lpParameter);

CGRSWinSock2Fun* g_pMSWInSock2Fun;

// IOCP���
HANDLE  g_hIOCP = nullptr;
// WinSock2 �����ӿ���
CGRSWinSock2Fun* g_pWinSock2Fun = nullptr;
// �߳̾������
CGRSHandleArray g_arThread;
// SOCKET �������
CGRSSocketArray g_arSocket;
// �Զ���Overlapped�ṹ��ָ������
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

        //����IOCP�ں˶���,������󲢷�CPU�������߳�
        g_hIOCP = ::CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, dwProcessorCnt);
        if (nullptr == g_hIOCP)
        {
            GRS_PRINTF(_T("[%8u]: ��ɶ˿ڴ���ʧ�ܣ������˳���\n"), GetCurrentThreadId());
            AtlThrowLastWin32();
        }

        //ʵ�ʴ���2��CPU�������߳�
        for (DWORD i = 0; i < dwProcessorCnt; i++)
        {
            g_arThread.Add(GRS_BEGINTHREAD(GRSIOCPThread, g_hIOCP));
        }
        GRS_PRINTF(_T("[%8u]: [%u]���̱߳�������\n"), GetCurrentThreadId(), g_arThread.GetCount());


        sockaddr_in stServerIP = {};
        stServerIP.sin_family = AF_INET;
        stServerIP.sin_port = htons(GRS_SERVER_PORT); // ע�⻥�������Ǵ����
        LPCTSTR pszTerminator = _T("");
        // Ĭ���ǰ󵽱��ص�ַ��0.0.0.0) �ڶ����ڶ�IPϵͳ�У����൱�������е�IP�϶�����
        ::RtlIpv4StringToAddress(GRS_SERVER_IP, TRUE, &pszTerminator, &stServerIP.sin_addr);
        
        sockaddr_in stLocalIP = {};
        stLocalIP.sin_family = AF_INET;
        stLocalIP.sin_addr.s_addr = INADDR_ANY; // ���ذ󶨵ĵ�ַ����Ĭ�ϵ� 0.0.0.0 ��������ͨ�����п��ܵ�·��;�����ӵ������
        stLocalIP.sin_port = htons((short)0);	// ʹ��0��ϵͳ�Զ�����

        //����AcceptEx����
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

            //��SOCKET�������ɶ˿ڶ����
            ::CreateIoCompletionPort((HANDLE)pOLConnectEx->m_skConnect, g_hIOCP, 0, 0);

            //�����ַ����
            //::setsockopt(pOLConnectEx->m_skConnect, SOL_SOCKET, SO_REUSEADDR, (char*)&on, sizeof(on));

            // ConnectExҪ����Ҫ��һ�����صĵ�ַ�Ͷ˿�
            result = ::bind(pOLConnectEx->m_skConnect, (LPSOCKADDR)&stLocalIP, sizeof(SOCKADDR_IN));

            ::getsockname(pOLConnectEx->m_skConnect, (SOCKADDR*)&pOLConnectEx->m_saLocal, &pOLConnectEx->m_iLocalLen);

            RtlIpv4AddressToStringEx(&pOLConnectEx->m_saLocal.sin_addr
                , pOLConnectEx->m_saLocal.sin_port
                , pOLConnectEx->m_pszAddrLocal
                , &pOLConnectEx->m_ulAddrLocalLen);

            GRS_PRINTF(_T("[%8u]: SOCKET[0x%08x]�󶨱������ַΪ[%s]��\n")
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

                    GRS_PRINTF(_T("[%8u]:  ����ConnectExʧ��,������:%d\n"), GetCurrentThreadId(), iError);
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

        //���߳̽���ȴ�״̬
        GRS_PRINTF(_T("[%8u]: ���߳̽���ȴ�״̬����\'q\'���˳���\n"), GetCurrentThreadId());
        //���߳̽���ȴ�״̬
        INPUT_RECORD sinfo = {};
        DWORD recnum = 0;
        HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
        while (ReadConsoleInput(hIn, &sinfo, 1, &recnum))
        {
            if (sinfo.EventType != KEY_EVENT)
            {
                continue;//����������������
            }
            //�жϰ���״̬(�Է���������������)
            if (sinfo.Event.KeyEvent.uChar.UnicodeChar == L'q')
            {
                break;
            }
        }
        GRS_PRINTF(_T("[%8u]: ���߳̽ӵ��˳���Ϣ......\n"), GetCurrentThreadId());

        ST_GRS_MY_WSAOVERLAPPED CloseOL = {};
        //��IOCP�̳߳ط����˳���Ϣ ���ñ�־FD_CLOSE��־
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

        //�ͷ�SOCKET��ST_GRS_MY_WSAOVERLAPPED��Դ
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
    {//������COM�쳣
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

//IOCP�̳߳��̺߳���
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
        
        WCHAR pszSendMsg[] = _T("��һָ��ɳ ���㽦���˻� ��������ӽ� ն�����ϼ\
            �μ��Ͻ�� ͷ������ɴ  ����һ�� ̫��ø��� ��һƪ�л� ����Խ����  ���ҹ������� ��ɽ�ݷ��� ƾ�������� ����С������\
            �������� ����װ����  �������� �ʹ�ɳ ������Ǯ��Ƽ� ������ ˭�˻�  ���ٴ����纮ѻ �������� �ʹ�ɳ �˼����ĸ�����\
            ̾���� �ƻƻ� �ʹ��������˴� �������� �ʹ�ɳ ������Ǯ��Ƽ� ������ ˭�˻� ���ٴ����纮ѻ �������� �ʹ�ɳ  �˼����ĸ�����\
            ̾���� �ƻƻ�  �ʹ��������˴� ��һƪ�л� ����Խ���� ���ҹ������� ��ɽ�ݷ��� ƾ�������� ����С������ �������� ����װ����\
            �������� �ʹ�ɳ ������Ǯ��Ƽ� ������ ˭�˻� ���ٴ����纮ѻ �������� �ʹ�ɳ �˼����ĸ����� ̾���� �ƻƻ� �ʹ��������˴�\
            �������� �ʹ�ɳ ������Ǯ��Ƽ� ������ ˭�˻� ���ٴ����纮ѻ �������� �ʹ�ɳ �˼����ĸ����� ̾���� �ƻƻ� �ʹ��������˴�\
            �������� �ʹ�ɳ ������Ǯ��Ƽ� ������ ˭�˻� ���ٴ����纮ѻ �������� �ʹ�ɳ �˼����ĸ����� ̾���� �ƻƻ� �ʹ��������˴�\
            �������� �ʹ�ɳ ������Ǯ��Ƽ� ������ ˭�˻� ���ٴ����纮ѻ �������� �ʹ�ɳ �˼����ĸ����� ̾���� �ƻƻ� �ʹ��������˴�");
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
                {// ������TIMER_WAIT ��������һ��
                    GRS_SLEEP(1000);

					GRS_PRINTF(_T("[%8u]: SOCKET[0x%08x] ��������0x%08X�����ԣ����·������ӣ�Զ��IP[%s]��\n")
						, GetCurrentThreadId()
						, pMyOl->m_skConnect
						, pMyOl->m_wsaOL.Internal
						, pMyOl->m_pszAddrRemot);

					//pMyOl->m_dwFlags = 0;
					//pMyOl->m_lOperation = FD_CONNECT;

					//// ���ճɹ�,���¶������ӳ�
					//// ���������������ͣ����գ��������������
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
                    GRS_PRINTF(_T("[%8u]: IOCPThread: GetQueuedCompletionStatus ����ʧ��,������: 0x%08x �ڲ�������[0x%08x]\n")
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
                GRS_PRINTF(_T("[%8u]: ��ɲ���\"ConnectEx\"��Զ��IP[%s]����ʼ�������ݣ�\n")
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
                //�ر��׽����ϵķ��ͻ��壬���������������
                ::setsockopt(pMyOl->m_skConnect,SOL_SOCKET,SO_SNDBUF,(const char*)&iBufLen,sizeof(int));
                ::setsockopt(pMyOl->m_skConnect,SOL_SOCKET,SO_RCVBUF,(const char*)&iBufLen,sizeof(int));

                //ǿ�Ʒ�����ʱ�㷨�ر�,ֱ�ӷ��͵�������ȥ
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
                // ע��ֱ�Ӱ���Ϣ���巢��ȥ��������ֻ���ģ����Թ���һ�龲̬������û�������
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
                GRS_PRINTF(_T("[%8u]: ��ɲ���\"WSASend\",����(0x%08x)����(%u bytes),ʵ�ʴ���( %u : %u )\n")
                    , GetCurrentThreadId()
                    , pMyOl->m_wsaBuf.buf
                    , pMyOl->m_wsaBuf.len
                    , dwBytesTransfered
                    , pMyOl->m_dwTrasBytes);

                // �����0�������Ǳ���ģ�����Ϊ����֤����ȷʵ�Ǵӷ���˽��յķ��ص����ݣ�������һ��
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
                GRS_PRINTF(_T("[%8u]: ��ɲ���\"WSARecv\",����(0x%08x)����(%u bytes),ʵ�ʴ���( %u : %u )\nECHO: %s\n")
                    , GetCurrentThreadId()
                    , pMyOl->m_wsaBuf.buf
                    , pMyOl->m_wsaBuf.len
                    , dwBytesTransfered
                    , pMyOl->m_dwTrasBytes
                    , pMyOl->m_wsaBuf.buf);

                pMyOl->m_lOperation = FD_CLOSE;
                pMyOl->m_dwFlags = 0;
                //����SOCKET
                ::shutdown(pMyOl->m_skConnect, SD_BOTH);
                g_pMSWInSock2Fun->DisconnectEx(pMyOl->m_skConnect, (LPOVERLAPPED)pMyOl, TF_REUSE_SOCKET, 0);

            }
            break;
            case FD_CLOSE:
            {
                if ( INVALID_SOCKET == pMyOl->m_skConnect )
                {
                    bLoop = FALSE;//�˳�ѭ��
                }
                else
                {
                    GRS_PRINTF(_T("[%8u]: ��ɲ���\"DisconnectEx\",����SOCKET[0x%08x]�ɹ������·������ӣ�Զ��IP[%s]��\n")
                        , GetCurrentThreadId()
                        , pMyOl->m_skConnect
                        , pMyOl->m_pszAddrRemot);

                    sockaddr_in stLocalIP = {};
                    stLocalIP.sin_family = AF_INET;
                    stLocalIP.sin_addr.s_addr = INADDR_ANY; // ���ذ󶨵ĵ�ַ����Ĭ�ϵ� 0.0.0.0 ��������ͨ�����п��ܵ�·��;�����ӵ������
                    stLocalIP.sin_port = htons((short)0);	// ʹ��0��ϵͳ�Զ�����

                    //�����ַ����
                    const int on = 1;
                    //::setsockopt(pMyOl->m_skConnect, SOL_SOCKET, SO_REUSEADDR, (char*)&on, sizeof(on));
                    ::bind(pMyOl->m_skConnect, (LPSOCKADDR)&stLocalIP, sizeof(SOCKADDR_IN));

                    ::getsockname(pMyOl->m_skConnect, (SOCKADDR*)&pMyOl->m_saLocal, &pMyOl->m_iLocalLen);

                    RtlIpv4AddressToStringEx(&pMyOl->m_saLocal.sin_addr
                        , pMyOl->m_saLocal.sin_port
                        , pMyOl->m_pszAddrLocal
                        , &pMyOl->m_ulAddrLocalLen);

                    GRS_PRINTF(_T("[%8u]: SOCKET[0x%08x]���µ�ַΪ[%s]��\n")
                        , GetCurrentThreadId()
                        , pMyOl->m_skConnect
                        , pMyOl->m_pszAddrLocal);

                    pMyOl->m_dwFlags = 0;
                    pMyOl->m_lOperation = FD_CONNECT;
                    
                    // ���ճɹ�,���¶������ӳ�
                    // ���������������ͣ����գ��������������
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
    {//������COM�쳣
        e;
        iRet = e.m_hr;
    }
    catch (...)
    {
        iRet = -1;
    }
    GRS_PRINTF(_T("[%8u]: IOCP�߳��˳�[Code: 0x%08x]��\n"), GetCurrentThreadId(), iRet);
    return iRet;
}
