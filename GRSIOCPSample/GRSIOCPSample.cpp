
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

// ��������������ĺ궨��
#define GRS_USEPRINTF() TCHAR pOutBufT[1024] = {};CHAR pOutBufA[1024] = {};
#define GRS_PRINTF(...) \
    StringCchPrintf(pOutBufT,1024,__VA_ARGS__);\
    WriteConsole(GetStdHandle(STD_OUTPUT_HANDLE),pOutBufT,lstrlen(pOutBufT),nullptr,nullptr);
#define GRS_PRINTFA(...) \
    StringCchPrintfA(pOutBufA,1024,__VA_ARGS__);\
    WriteConsoleA(GetStdHandle(STD_OUTPUT_HANDLE),pOutBufA,lstrlenA(pOutBufA),nullptr,nullptr);

// �ڴ����ĺ궨��
#define GRS_ALLOC(sz)		::HeapAlloc(GetProcessHeap(),0,(sz))
#define GRS_CALLOC(sz)		::HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,(sz))
#define GRS_CREALLOC(p,sz)	::HeapReAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,(p),(sz))
#define GRS_SAFEFREE(p)		if( nullptr != (p) ){ ::HeapFree( ::GetProcessHeap(),0,(p) ); (p) = nullptr; }

// �����̵߳ĺ궨��
#define GRS_BEGINTHREAD(Fun,Param) (HANDLE)_beginthreadex(nullptr,0,(_beginthreadex_proc_type)(Fun),(Param),0,nullptr)

// һЩĬ�ϲ�������Щ�������Զ��嵽�����ļ���ȥ������INI��XML��Lua��
#define GRS_SERVER_IP                   _T("0.0.0.0")  // Ĭ�ϼ���IP��ַ��ע�����������IPϵͳ����Ҫ����������ʱ����Ҫ��ȷָ���������ĸ�IP��
#define GRS_SERVER_PORT                 8080    // �����˿�
#define GRS_DATA_BUFSIZE_DEFAULT        4096    // Ĭ�����ݻ����С
#define GRS_DATA_BUF_GROW_SIZE          4096    // ���ݻ���������С
#define GRS_THREAD_POOL_THREAD_COUNT    0       // Ĭ���������߳���������Ϊ0ʱ���Զ�����ϵͳ�߼��ں����������������߳�
#define GRS_MAX_LISTEN_SOCKET           5       // ���ͬʱ������SOCKET����ʵ���ǲ��е�Accept������ѭ��ʹ�þͿ�����ɸ߲�����Ӧ

// �������Զ���Overlapped�ṹ����غ�ͽṹ�嶨��
// ע�Ᵽ�����ڲ����ݵ�ԭ���ԣ���Ҫǣ��ȫ�ֱ����������̵߳Ķ���
// �������Ҫ���е�Ч�Ŀ��߳�ͬ�����ʣ���ʧȥ��ʹ�ö��߳�SOCKET�ص�����
#define GRS_ADDR_STR_LEN            36
#define GRS_WSABUF_COUNT_DEFAULT    1

struct ST_GRS_MY_WSAOVERLAPPED
{
    WSAOVERLAPPED m_wsaOL;
    SOCKET        m_skLocal;        // �����׽��־��
    SOCKET        m_skRemote;       // Ͷ�ݲ�����SOCKET��� Ҳ��������Զ�˵�SOCKET

    ULONG         m_ulAddrLocalLen;
    ULONG         m_ulAddrRemotLen;
    TCHAR         m_pszAddrLocal[GRS_ADDR_STR_LEN];
    TCHAR         m_pszAddrRemot[GRS_ADDR_STR_LEN];
                                                    
    INT           m_iLocalLen;
    SOCKADDR_IN*  m_psaLocal;
    INT           m_iRemoteLen;
    SOCKADDR_IN*  m_psaRemote;
        
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
        // �����д������
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

        // ����IOCP�ں˶���,������󲢷�CPU�������߳�
        g_hIOCP = ::CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, dwProcessorCnt);
        if ( nullptr == g_hIOCP )
        {
            GRS_PRINTF(_T("[%8u]: ��ɶ˿ڴ���ʧ�ܣ������˳���\n"), GetCurrentThreadId());
            AtlThrowLastWin32();
        }

        // ����CPU�������߳�
        for ( DWORD i = 0; i < dwProcessorCnt; i++ )
        {
            g_arThread.Add( GRS_BEGINTHREAD(GRSIOCPThread, g_hIOCP) );
        }

        GRS_PRINTF(_T("[%8u]: [%u]���̱߳�������\n"), GetCurrentThreadId(), g_arThread.GetCount());

        // ����������Listen�����
        skListen = ::WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, WSA_FLAG_OVERLAPPED);

        // ��SOCKET�������ɶ˿ڶ����
        // ע��������׽���һ��Ҫ�Ⱥ�IOCP��,����AcceptEx���޷�����IOCP����
        ::CreateIoCompletionPort((HANDLE)skListen, g_hIOCP, 0, 0);

        sockaddr_in service;
        service.sin_family = AF_INET;
        service.sin_port = htons(GRS_SERVER_PORT); // ע�⻥�������Ǵ����

        LPCTSTR pszTerminator = _T("");
        // Ĭ���ǰ󵽱��ص�ַ��0.0.0.0) �ڶ����ڶ�IPϵͳ�У����൱�������е�IP�϶�����
        ::RtlIpv4StringToAddress(GRS_SERVER_IP, TRUE, &pszTerminator, &service.sin_addr);

        //service.sin_addr.s_addr = INADDR_ANY;      

        if ( 0 != ::bind(skListen, (SOCKADDR*)&service, sizeof(SOCKADDR)) )
        {
            GRS_PRINTF( _T("[%8u]: �󶨵�IP[%s:%d]ʧ�ܣ�������[0x%08X],�����˳���\n")
                , GetCurrentThreadId()
                , GRS_SERVER_IP
                , GRS_SERVER_PORT
                , ::WSAGetLastError());
            AtlThrowLastWin32();
        }

        // ע������ָ���������ܵ��������д�С��ʵ��ֵ��ϵͳ�ڲ�ȷ��
        if (0 != ::listen(skListen, SOMAXCONN))
        {
            GRS_PRINTF( _T("[%8u]: ��������ʧ�ܣ�������[0x%08X],�����˳���\n")
                , GetCurrentThreadId()
                , ::WSAGetLastError());
            AtlThrowLastWin32();
        }
        
        GRS_PRINTF( _T("[%8u]: Server IP[%s:%d] Start Listening...\n\n"), GetCurrentThreadId(), GRS_SERVER_IP, GRS_SERVER_PORT );

        //����AcceptEx����
        for ( int i = 0; i < iMaxAcceptEx; i++ )
        {
            skAccept = ::WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, WSA_FLAG_OVERLAPPED);
            g_arSocket.Add(skAccept);

            pOLAcceptEx = (ST_GRS_MY_WSAOVERLAPPED*)GRS_CALLOC(sizeof(ST_GRS_MY_WSAOVERLAPPED));
            ATLASSERT(nullptr != pOLAcceptEx); // ��ʽ����������Ҫ�жϲ���ȷ��ֹ

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

            //��SOCKET�������ɶ˿ڶ����
            ::CreateIoCompletionPort((HANDLE)skAccept, g_hIOCP, 0, 0);

            // ע����0���峤�ȵ���AcceptEx��������ֹ�������Ӳ������ݵ���AcceptExһֱ�޷����أ�����Ϊ������
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
                    
                    // ����������ɾ����ֻ����Ϊ��Чֵ
                    g_arSocket.SetAt(i, INVALID_SOCKET);
                    g_arOverlapped.SetAt(i, nullptr);

                    GRS_PRINTF(_T("[%8u]: ����AcceptExʧ��,������:%d\n"), GetCurrentThreadId(), iError);
                    continue;
                }
            }

            GRS_PRINTF(_T("[%8u]: (%d)SOCKERT[0x%08X] AcceptEx...\n"), GetCurrentThreadId(), i , skAccept);
        }

        GRS_PRINTF(_T("[%8u]: ���߳̽���ȴ�״̬����\'q\'���˳���\n"), GetCurrentThreadId());
        //���߳̽���ȴ�״̬
        INPUT_RECORD sinfo = {};
        DWORD recnum = 0;
        HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
        while ( ReadConsoleInput(hIn, &sinfo, 1, &recnum) )
        {
            if ( sinfo.EventType != KEY_EVENT )
            {
                continue;//����������������
            }
            //�жϰ���״̬(�Է���������������)
            if ( sinfo.Event.KeyEvent.uChar.UnicodeChar == L'q')
            {
                break;
            }
        }
     
        GRS_PRINTF(_T("[%8u]: ���߳̽ӵ��˳���Ϣ......\n"), GetCurrentThreadId());
        //��IOCP�̳߳ط����˳���Ϣ ���ñ�־FD_CLOSE��־
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

        //�ͷ�SOCKET��ST_GRS_MY_WSAOVERLAPPED��Դ
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
    //----------------------------------------------------------------------------------
    // ע��������кܶ� GetCurrentThreadId() �ĵ��ã��⿴��ȥ���񲻱�Ҫ����ȫ����
    // �ñ������洢���ֵ�����ǲ�Ҫ��������һ�����̵߳��̺߳�����ÿ�α�����ʱ���п���
    // �ǲ�ͬ���̣߳�����ÿ����Ҫ֪�����ĸ��߳�ʱ����Ҫ��ȡ����̺߳�����ʱ���߳�ID
    // �����ھֲ������е�IDֵ���ܲ�������ʵ�ĵ�ǰ�̵߳�ID
    // ��Ȼ�ִ���Windows�̵߳����㷨�Ѿ���ֿ������̵߳���Ե�ԣ������ϲ������ͬ
    // һ���̺߳�����ʵ������˵ͬһ���߳������Ļ��������ȵ���ͬ��CPU�߼�����ȥ��
    // ���������������Ǿ��Կɿ�������
    // ����Ϊ��׼ȷ֪�����ĸ��߳��ڵ��õ�ǰʵ�����ͱ���ʱ�̵��� GetCurrentThreadId() ����֪
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
                // ����ʵ���л���Ҫ��һ���ж� pKey �� lpOverlapped ͬΪ nullptr ����ǿ���ȷ�����˳���Ϣ
                // ������Ǹ������֪ͨ ��Ҫ�� DisConnectEX ���� Socket

                GRS_PRINTF(_T("[%8u]: GRSIOCPThread: GetQueuedCompletionStatus ����ʧ��,������:[0x%08x] �ڲ�������[0x%08x]\n")
                    , GetCurrentThreadId()
                    , GetLastError()
                    , lpOverlapped ? lpOverlapped->Internal : WSAGetLastError() );

                AtlThrowLastWin32();
            }

            switch ( pstCurrentTransOL->m_lOperation )
            {// ����Ĳ����൱��һ��״̬��
            case FD_ACCEPT:
            {
                GRS_PRINTF(_T("[%8u]: ��ɲ���\"AcceptEx\",����(0x%08x)����(%u bytes),ʵ�ʴ���( %u : %u )\n")
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

                GRS_PRINTF(_T("[%8u]: Զ��IP[%s]���ӽ���,����IP[%s]\n")
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
                //�ر��׽����ϵķ��ͻ��壬���������������
                ::setsockopt(pstCurrentTransOL->m_skRemote, SOL_SOCKET, SO_SNDBUF, (const char*)&iBufLen, sizeof(int));
                ::setsockopt(pstCurrentTransOL->m_skRemote, SOL_SOCKET, SO_RCVBUF, (const char*)&iBufLen, sizeof(int));

                //ǿ�Ʒ�����ʱ�㷨�ر�,ֱ�ӷ��͵�������ȥ
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

                // ��������Ҫ��Ϣͨ����չOVERLAPPED�Ľṹ�����ص�������ȥ
                // ע���������ֻ��һ��Echo�����������Ե���Accept��ɺ󣬾͵���WSAResvǨ�Ƶ�Read״̬ȥ
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
                        GRS_PRINTF(_T("[%8u]: WSARecv��������[0x%08x]\n"), GetCurrentThreadId(), iErrorCode);
                    }
                }
            }
            break;
            case FD_WRITE:
            {
                GRS_PRINTF(_T("[%8u]: ��ɲ���\"WSASend\",Զ��IP[%s],����(0x%08x)����(%u Bytes),ʵ�ʴ���( %u : %u )\n")
                    , GetCurrentThreadId()
                    , pstCurrentTransOL->m_pszAddrRemot
                    , pstCurrentTransOL->m_pBuf
                    , pstCurrentTransOL->m_szBufLen 
                    , dwBytesTransfered
                    , pstCurrentTransOL->m_dwTrasBytes);

                //shutdown(pstCurrentTransOL->m_skRemote, SD_BOTH);

                pstCurrentTransOL->m_lOperation = FD_CLOSE;
                pstCurrentTransOL->m_dwTrasBytes = 0;

                //����SOCKET
                g_pWinSock2Fun->DisconnectEx(pstCurrentTransOL->m_skRemote, (LPOVERLAPPED)pstCurrentTransOL, TF_REUSE_SOCKET, 0);
            }
            break;
            case FD_READ:
            {
                GRS_PRINTF(_T("[%8u]: ��ɲ���\"WSARecv\",Զ��IP[%s],����(0x%08x)����(%u Bytes),ʵ�ʽ���( %u : %u )���ж������Ƿ������ɣ�\n")
                    , GetCurrentThreadId()
                    , pstCurrentTransOL->m_pszAddrRemot
                    , pstCurrentTransOL->m_pBuf
                    , pstCurrentTransOL->m_szBufLen
                    , dwBytesTransfered
                    , pstCurrentTransOL->m_dwTrasBytes);

                if ( pstCurrentTransOL->m_dwTrasBytes < pstCurrentTransOL->m_wsaBuf.len )
                {// ʵ�ʽ��յ��ֽ���С�ڻ��峤�ȣ�˵��������ɣ������ٷ�һ������
                    pstCurrentTransOL->m_wsaBuf.buf = (CHAR*) pstCurrentTransOL->m_pBuf;
                    pstCurrentTransOL->m_wsaBuf.len = (ULONG)( pstCurrentTransOL->m_szBufLen <= szBufGrowLen 
                        ? pstCurrentTransOL->m_dwTrasBytes 
                        : pstCurrentTransOL->m_szBufLen - szBufGrowLen + pstCurrentTransOL->m_dwTrasBytes );

                    pstCurrentTransOL->m_lOperation = FD_WRITE;
                    pstCurrentTransOL->m_dwFlags = 0;
                    pstCurrentTransOL->m_dwTrasBytes = 0;

                    GRS_PRINTF(_T("[%8u]: Զ��IP[%s]������[%u Bytes]�Ѿ�������ɣ������ͻ�ȥ��\n")
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
                            GRS_PRINTF(_T("[%8u]: WSASend��������[0x%08x]\n"), GetCurrentThreadId(), iErrorCode);
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

                    // ע����ʽ�����в���Ҫ�ж��ڴ�����������Ҫ�жϻ��������Ȳ�Ҫ����ĳ���趨����ֵ����ֹ���⴫�����
                    // ���ߵ���Ҫ����ϴ󳤶ȵ����ݣ����ļ�ʱ�����ǽ�֮ǰ������ֱ��׷�ӵ�ָ�����ļ��У�Ȼ������ͬһ�黺��
                    // ��������ֻ���ж����ڴ滹�ܲ��ܷ���
                    ATLASSERT( nullptr != pstCurrentTransOL->m_pBuf );

                    pstCurrentTransOL->m_wsaBuf.buf = (CHAR*)pstCurrentTransOL->m_pBuf + szOldBufLen;
                    pstCurrentTransOL->m_wsaBuf.len = (ULONG)szBufGrowLen;
                    // ��������Ҫ��Ϣͨ����չOVERLAPPED�Ľṹ�����ص�������ȥ
                    // ע���������ֻ��һ��Echo�����������Ե���Accept��ɺ󣬾͵���WSAResvǨ�Ƶ�Read״̬ȥ
                    pstCurrentTransOL->m_lOperation = FD_READ;
                    pstCurrentTransOL->m_dwFlags = 0;
                    pstCurrentTransOL->m_dwTrasBytes = 0;

                    GRS_PRINTF(_T("[%8u]: Զ��IP[%s]������δ������ɣ��ѽ���[%u Bytes]������[%u Bytes]�������н��գ�\n")
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
                            GRS_PRINTF(_T("[%8u]: WSARecv��������[0x%08x]\n"), GetCurrentThreadId(), iErrorCode);
                        }
                    }
                }
            }
            break;
            case FD_CLOSE:
            {
                if ( INVALID_SOCKET == pstCurrentTransOL->m_skRemote )
                {
                    GRS_PRINTF(_T("[%8u]: IOCP�̵߳õ��˳�֪ͨ,IOCP�߳��˳�\n"),
                        GetCurrentThreadId());

                    bLoop = FALSE;//�˳�ѭ��
                }
                else
                {
                    GRS_PRINTF(_T("[%8u]: ��ɲ���\"DisconnectEx\",����(0x%08x)����(%u bytes),����SOCKET[0x%08x]�ɹ�,����AcceptEx......\n")
                        , GetCurrentThreadId()
                        , pstCurrentTransOL->m_pBuf
                        , pstCurrentTransOL->m_szBufLen 
                        , pstCurrentTransOL->m_skRemote);

                    // ����ָ�Ĭ�ϴ�С
                    if( pstCurrentTransOL->m_szBufLen > GRS_DATA_BUFSIZE_DEFAULT )
                    {
                        pstCurrentTransOL->m_szBufLen = GRS_DATA_BUFSIZE_DEFAULT;
                        pstCurrentTransOL->m_pBuf = GRS_CREALLOC(pstCurrentTransOL->m_pBuf, pstCurrentTransOL->m_szBufLen);
                    }
 
                    pstCurrentTransOL->m_lOperation = FD_ACCEPT;
                    pstCurrentTransOL->m_dwFlags = 0;
                    pstCurrentTransOL->m_dwTrasBytes = 0;

                    //���ճɹ�,���¶������ӳ�
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
	{//������COM�쳣
		e;
        nRet = e.m_hr;
	}
	catch (...)
	{
        nRet = -1;
	}
    GRS_PRINTF(_T("[%8u]: IOCP�߳��˳�[Code: 0x%08x]��\n"), GetCurrentThreadId(), nRet);

    return nRet;
}
