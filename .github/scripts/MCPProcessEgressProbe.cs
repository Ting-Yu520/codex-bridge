using System;
using System.Net;
using System.Net.Sockets;

internal static class MCPProcessEgressProbe
{
    private static int Main()
    {
        try
        {
            if (!ProbeLoopback(AddressFamily.InterNetwork, IPAddress.Loopback)) return 10;
            if (!Socket.OSSupportsIPv6 || !ProbeLoopback(AddressFamily.InterNetworkV6, IPAddress.IPv6Loopback)) return 13;
            if (!IsBlocked(AddressFamily.InterNetwork, IPAddress.Parse("192.0.2.1"))) return 11;
            if (!IsBlocked(AddressFamily.InterNetworkV6, IPAddress.Parse("2001:db8::1"))) return 14;
            return 0;
        }
        catch
        {
            return 12;
        }
    }

    private static bool ProbeLoopback(AddressFamily family, IPAddress address)
    {
        using (var listener = new TcpListener(address, 0))
        {
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            var accept = listener.BeginAcceptTcpClient(null, null);
            using (var localClient = new TcpClient(family))
            {
                var connect = localClient.BeginConnect(address, port, null, null);
                if (!connect.AsyncWaitHandle.WaitOne(2500)) return false;
                localClient.EndConnect(connect);
                using (listener.EndAcceptTcpClient(accept)) { }
            }
            return true;
        }
    }

    private static bool IsBlocked(AddressFamily family, IPAddress address)
    {
        using (var externalClient = new TcpClient(family))
        {
            try
            {
                var connect = externalClient.BeginConnect(address, 65000, null, null);
                connect.AsyncWaitHandle.WaitOne(3500);
                if (!connect.IsCompleted) return true;
                externalClient.EndConnect(connect);
                return !externalClient.Connected;
            }
            catch (SocketException)
            {
                return true;
            }
        }
    }
}
