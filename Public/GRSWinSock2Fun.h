
#pragma once

#include <SDKDDKVer.h>
#define WIN32_LEAN_AND_MEAN // 从 Windows 头中排除极少使用的资料
#include <windows.h>
#include <tchar.h>
#include <atltrace.h>
#include <atlexcept.h>
#include <Winsock2.h>
#include <MSWSOCK.h> 	

#pragma comment( lib, "Ws2_32.lib" )
#pragma comment( lib, "Mswsock.lib" )

#define GRS_WINSOCK_VH 2
#define GRS_WINSOCK_VL 2

using namespace ATL;

class CGRSWinSock2Fun
{
protected:
    CGRSWinSock2Fun( SOCKET skTemp )
    {
        SetupWinSock2();
        LoadAllFun(skTemp);
    }
    CGRSWinSock2Fun(int af, int type, int protocol)
    {
        SetupWinSock2();
        LoadAllFun(af, type, protocol);
    }
protected:
    virtual ~CGRSWinSock2Fun(void)
    {
        CleanupWinSock2();
    }
private:
    CGRSWinSock2Fun() = delete;
    CGRSWinSock2Fun(CGRSWinSock2Fun const&) = delete;
    CGRSWinSock2Fun& operator=(CGRSWinSock2Fun const&) = delete;
protected:
    BOOL LoadWSAFun(SOCKET& skTemp, GUID& funGuid, void*& pFun)
    {
        DWORD dwBytes = 0;
        BOOL bRet = TRUE;
        pFun = nullptr;
        if (INVALID_SOCKET == skTemp)
        {
            ATLTRACE(_T("传入了空的SOCKET句柄,无法完成扩展函数的载入!"));
            return FALSE;
        }

        if (SOCKET_ERROR == ::WSAIoctl(skTemp,
            SIO_GET_EXTENSION_FUNCTION_POINTER,
            &funGuid,
            sizeof(funGuid),
            &pFun,
            sizeof(pFun),
            &dwBytes,
            nullptr,
            nullptr))
        {
            pFun = nullptr;
            return FALSE;
        }
#ifdef _DEBUG
        {
            GUID Guid = WSAID_ACCEPTEX;
            if (IsEqualGUID(Guid, funGuid))
            {
                ATLTRACE(_T("AcceptEx 加载成功!\n"));
            }
        }

        {
            GUID Guid = WSAID_CONNECTEX;
            if (IsEqualGUID(Guid, funGuid))
            {
                ATLTRACE(_T("ConnectEx 加载成功!\n"));
            }
        }

        {
            GUID Guid = WSAID_DISCONNECTEX;
            if (IsEqualGUID(Guid, funGuid))
            {
                ATLTRACE(_T("DisconnectEx 加载成功!\n"));
            }
        }

        {
            GUID Guid = WSAID_GETACCEPTEXSOCKADDRS;
            if (IsEqualGUID(Guid, funGuid))
            {
                ATLTRACE(_T("GetAcceptExSockaddrs 加载成功!\n"));
            }
        }
        {
            GUID Guid = WSAID_TRANSMITFILE;
            if (IsEqualGUID(Guid, funGuid))
            {
                ATLTRACE(_T("TransmitFile 加载成功!\n"));
            }

        }
        {
            GUID Guid = WSAID_TRANSMITPACKETS;
            if (IsEqualGUID(Guid, funGuid))
            {
                ATLTRACE(_T("TransmitPackets 加载成功!\n"));
            }

        }
        {
            GUID Guid = WSAID_WSARECVMSG;
            if (IsEqualGUID(Guid, funGuid))
            {
                ATLTRACE(_T("WSARecvMsg 加载成功!\n"));
            }
        }

#if(_WIN32_WINNT >= 0x0600)
        {
            GUID Guid = WSAID_WSASENDMSG;
            if (IsEqualGUID(Guid, funGuid))
            {
                ATLTRACE(_T("WSASendMsg 加载成功!\n"));
            }
        }
#endif

#endif
        return nullptr != pFun;
    }
protected:
    LPFN_ACCEPTEX m_pfnAcceptEx;
    LPFN_CONNECTEX m_pfnConnectEx;
    LPFN_DISCONNECTEX m_pfnDisconnectEx;
    LPFN_GETACCEPTEXSOCKADDRS m_pfnGetAcceptExSockaddrs;
    LPFN_TRANSMITFILE m_pfnTransmitfile;
    LPFN_TRANSMITPACKETS m_pfnTransmitPackets;
    LPFN_WSARECVMSG m_pfnWSARecvMsg;
#if(_WIN32_WINNT >= 0x0600)
    LPFN_WSASENDMSG m_pfnWSASendMsg;
#endif
protected:
    static BOOL SetupWinSock2()
    {
        BOOL bRet = TRUE;
        try
        {
            WORD wVer = MAKEWORD(GRS_WINSOCK_VH, GRS_WINSOCK_VL);
            WSADATA stWD = {};
            int err = ::WSAStartup(wVer, &stWD);
            if (0 != err)
            {
                ATLTRACE(_T("无法初始化Socket2系统环境，错误码为：%d！\n")
                    , ::WSAGetLastError() );
                AtlThrowLastWin32();
            }
            if (LOBYTE(stWD.wVersion) != GRS_WINSOCK_VH ||
                HIBYTE(stWD.wVersion) != GRS_WINSOCK_VL)
            {
                ATLTRACE(_T("无法初始化%d.%d版本的WinSocket环境！\n")
                    , GRS_WINSOCK_VH, GRS_WINSOCK_VL);
                ::WSACleanup();
                AtlThrowLastWin32();
            }
            ATLTRACE(_T("Winsock库初始化成功!\n\t当前系统中支持最高的WinSock版本为%d.%d\n\t当前应用加载的版本为%d.%d\n")
                , LOBYTE(stWD.wHighVersion), HIBYTE(stWD.wHighVersion)
                , LOBYTE(stWD.wVersion), HIBYTE(stWD.wVersion));
        }
        catch (CAtlException& e)
        {//发生了COM异常
            e;
            bRet = FALSE;
        }
        catch (...)
        {
            bRet = FALSE;
        }
        return bRet;

    }
    static void CleanupWinSock2()
    {
        ::WSACleanup();
    }
protected:
    static CGRSWinSock2Fun* ms_pWinSock2;
public:
    static CGRSWinSock2Fun* GetInstance()
    {
        if (nullptr == ms_pWinSock2)
        {
            ms_pWinSock2 = new CGRSWinSock2Fun(INVALID_SOCKET);
        }
        return ms_pWinSock2;
    }
    static CGRSWinSock2Fun* GetInstance(int af, int type, int protocol)
    {
        ATLASSERT(nullptr == ms_pWinSock2);
        if ( nullptr == ms_pWinSock2 )
        {
            ms_pWinSock2 = new CGRSWinSock2Fun(af, type, protocol);
        }
        return ms_pWinSock2;
    }
    static void Destory()
    {
        ATLASSERT(nullptr != ms_pWinSock2);
        if ( nullptr != ms_pWinSock2 )
        {
            delete ms_pWinSock2;
            ms_pWinSock2 = nullptr;
        }
        ATLTRACE(_T("Winsock库已释放!\n"));
    }
protected:
    BOOL LoadAcceptExFun(SOCKET& skTemp)
    {
        GUID GuidAcceptEx = WSAID_ACCEPTEX;
        return LoadWSAFun(skTemp, GuidAcceptEx, (void*&)m_pfnAcceptEx);
    }

    BOOL LoadConnectExFun(SOCKET& skTemp)
    {
        GUID GuidAcceptEx = WSAID_CONNECTEX;
        return LoadWSAFun(skTemp, GuidAcceptEx, (void*&)m_pfnConnectEx);
    }

    BOOL LoadDisconnectExFun(SOCKET& skTemp)
    {
        GUID GuidDisconnectEx = WSAID_DISCONNECTEX;
        return LoadWSAFun(skTemp, GuidDisconnectEx, (void*&)m_pfnDisconnectEx);
    }

    BOOL LoadGetAcceptExSockaddrsFun(SOCKET& skTemp)
    {
        GUID GuidGetAcceptExSockaddrs = WSAID_GETACCEPTEXSOCKADDRS;
        return LoadWSAFun(skTemp, GuidGetAcceptExSockaddrs, (void*&)m_pfnGetAcceptExSockaddrs);
    }

    BOOL LoadTransmitFileFun(SOCKET& skTemp)
    {
        GUID GuidTransmitFile = WSAID_TRANSMITFILE;
        return LoadWSAFun(skTemp, GuidTransmitFile, (void*&)m_pfnTransmitfile);
    }

    BOOL LoadTransmitPacketsFun(SOCKET& skTemp)
    {
        GUID GuidTransmitPackets = WSAID_TRANSMITPACKETS;
        return LoadWSAFun(skTemp, GuidTransmitPackets, (void*&)m_pfnTransmitPackets);
    }

    BOOL LoadWSARecvMsgFun(SOCKET& skTemp)
    {
        GUID GuidWSARecvMsg = WSAID_WSARECVMSG;
        return LoadWSAFun(skTemp, GuidWSARecvMsg, (void*&)m_pfnWSARecvMsg);
    }

#if(_WIN32_WINNT >= 0x0600)
    BOOL LoadWSASendMsgFun(SOCKET& skTemp)
    {
        GUID GuidWSASendMsg = WSAID_WSASENDMSG;
        return LoadWSAFun(skTemp, GuidWSASendMsg, (void*&)m_pfnWSASendMsg);
    }
#endif

protected:
    BOOL LoadAllFun(SOCKET skTemp)
    {// 注意这个地方的调用顺序，是根据服务器的需要
     // 并结合了表达式副作用而特意安排的调用顺序
        BOOL bCreateSocket = FALSE;
        BOOL bRet = FALSE;

        if (INVALID_SOCKET == skTemp)
        {//如果传入空的SOCKET句柄,那么就默认以TCP协议来创建SOCKET句柄
            //这样加载的扩展函数只用于TCP协议工作
            skTemp = ::WSASocket(AF_INET,
                SOCK_STREAM,
                IPPROTO_TCP,
                nullptr,
                0,
                WSA_FLAG_OVERLAPPED);

            bCreateSocket = (skTemp != INVALID_SOCKET);
            if (!bCreateSocket)
            {
                ATLTRACE(_T("创建临时SOCKET句柄出错,错误码:0x%08X\n"), WSAGetLastError());
                return FALSE;
            }
        }

        bRet = (LoadAcceptExFun(skTemp) &&
            LoadGetAcceptExSockaddrsFun(skTemp) &&
            LoadTransmitFileFun(skTemp) &&
            LoadTransmitPacketsFun(skTemp) &&
            LoadDisconnectExFun(skTemp) &&
            LoadConnectExFun(skTemp) &&
            LoadWSARecvMsgFun(skTemp));

        if (bCreateSocket)
        {
            closesocket(skTemp);
        }
        return bRet;
    }
    BOOL LoadAllFun(int af, int type, int protocol)
    {
        BOOL bRet = FALSE;
        SOCKET skTemp = INVALID_SOCKET;

        skTemp = ::WSASocket(af,
            type,
            protocol,
            nullptr,
            0,
            WSA_FLAG_OVERLAPPED);

        if (INVALID_SOCKET == skTemp)
        {
            ATLTRACE(_T("创建临时SOCKET句柄出错,错误码:0x%08X\n"), WSAGetLastError());
            return FALSE;
        }

        bRet = (LoadAcceptExFun(skTemp) &&
            LoadGetAcceptExSockaddrsFun(skTemp) &&
            LoadTransmitFileFun(skTemp) &&
            LoadTransmitPacketsFun(skTemp) &&
            LoadDisconnectExFun(skTemp) &&
            LoadConnectExFun(skTemp) &&
            LoadWSARecvMsgFun(skTemp));

        if (INVALID_SOCKET != skTemp)
        {
            closesocket(skTemp);
        }
        return bRet;
    }
public:
    BOOL AcceptEx(
        SOCKET sListenSocket,
        SOCKET sAcceptSocket,
        PVOID lpOutputBuffer,
        DWORD dwReceiveDataLength,
        DWORD dwLocalAddressLength,
        DWORD dwRemoteAddressLength,
        LPDWORD lpdwBytesReceived,
        LPOVERLAPPED lpOverlapped
    )
    {
        ATLASSERT(nullptr != m_pfnAcceptEx);
        return m_pfnAcceptEx(sListenSocket,
            sAcceptSocket,
            lpOutputBuffer,
            dwReceiveDataLength,
            dwLocalAddressLength,
            dwRemoteAddressLength,
            lpdwBytesReceived,
            lpOverlapped);
    }

    BOOL ConnectEx(
        SOCKET s,
        const struct sockaddr FAR* name,
        int namelen,
        PVOID lpSendBuffer,
        DWORD dwSendDataLength,
        LPDWORD lpdwBytesSent,
        LPOVERLAPPED lpOverlapped
    )
    {
        ATLASSERT(nullptr != m_pfnConnectEx);
        return m_pfnConnectEx(
            s,
            name,
            namelen,
            lpSendBuffer,
            dwSendDataLength,
            lpdwBytesSent,
            lpOverlapped
        );
    }

    BOOL DisconnectEx(
        SOCKET s,
        LPOVERLAPPED lpOverlapped,
        DWORD  dwFlags,
        DWORD  dwReserved
    )
    {
        ATLASSERT(nullptr != m_pfnDisconnectEx);
        return m_pfnDisconnectEx(s,
            lpOverlapped,
            dwFlags,
            dwReserved);
    }

    VOID GetAcceptExSockaddrs(
        PVOID lpOutputBuffer,
        DWORD dwReceiveDataLength,
        DWORD dwLocalAddressLength,
        DWORD dwRemoteAddressLength,
        sockaddr** LocalSockaddr,
        LPINT LocalSockaddrLength,
        sockaddr** RemoteSockaddr,
        LPINT RemoteSockaddrLength
    )
    {
        ATLASSERT(nullptr != m_pfnGetAcceptExSockaddrs);
        return m_pfnGetAcceptExSockaddrs(
            lpOutputBuffer,
            dwReceiveDataLength,
            dwLocalAddressLength,
            dwRemoteAddressLength,
            LocalSockaddr,
            LocalSockaddrLength,
            RemoteSockaddr,
            RemoteSockaddrLength
        );
    }

    BOOL TransmitFile(
        SOCKET hSocket,
        HANDLE hFile,
        DWORD nNumberOfBytesToWrite,
        DWORD nNumberOfBytesPerSend,
        LPOVERLAPPED lpOverlapped,
        LPTRANSMIT_FILE_BUFFERS lpTransmitBuffers,
        DWORD dwReserved
    )
    {
        ATLASSERT(nullptr != m_pfnTransmitfile);
        return m_pfnTransmitfile(
            hSocket,
            hFile,
            nNumberOfBytesToWrite,
            nNumberOfBytesPerSend,
            lpOverlapped,
            lpTransmitBuffers,
            dwReserved
        );
    }

    BOOL TransmitPackets(
        SOCKET hSocket,
        LPTRANSMIT_PACKETS_ELEMENT lpPacketArray,
        DWORD nElementCount,
        DWORD nSendSize,
        LPOVERLAPPED lpOverlapped,
        DWORD dwFlags
    )
    {
        ATLASSERT(nullptr != m_pfnTransmitPackets);
        return m_pfnTransmitPackets(
            hSocket,
            lpPacketArray,
            nElementCount,
            nSendSize,
            lpOverlapped,
            dwFlags
        );
    }

    INT WSARecvMsg(
        SOCKET s,
        LPWSAMSG lpMsg,
        LPDWORD lpdwNumberOfBytesRecvd,
        LPWSAOVERLAPPED lpOverlapped,
        LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
    )
    {
        ATLASSERT(nullptr != m_pfnWSARecvMsg);
        return m_pfnWSARecvMsg(
            s,
            lpMsg,
            lpdwNumberOfBytesRecvd,
            lpOverlapped,
            lpCompletionRoutine
        );
    }

#if(_WIN32_WINNT >= 0x0600)
    INT WSASendMsg(
        SOCKET s,
        LPWSAMSG lpMsg,
        DWORD dwFlags,
        LPDWORD lpNumberOfBytesSent,
        LPWSAOVERLAPPED lpOverlapped,
        LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
    )
    {
        ATLASSERT(nullptr != m_pfnWSASendMsg);
        return m_pfnWSASendMsg(
            s,
            lpMsg,
            dwFlags,
            lpNumberOfBytesSent,
            lpOverlapped,
            lpCompletionRoutine
        );
    }
#endif
    /*WSAID_ACCEPTEX
    WSAID_CONNECTEX
    WSAID_DISCONNECTEX
    WSAID_GETACCEPTEXSOCKADDRS
    WSAID_TRANSMITFILE
    WSAID_TRANSMITPACKETS
    WSAID_WSARECVMSG
    WSAID_WSASENDMSG */

};