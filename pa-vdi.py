import asyncio
import aiodns
import socket


class UdpClientProtocol:
    def __init__(self, message, work_loop):
        self.message = message
        self.loop = work_loop
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport
        # print('Send:', self.message)
        self.transport.sendto(self.message.encode())

    def datagram_received(self, data, addr):
        # print("Received:", data.decode())
        # print("Close the socket")
        # self.transport.close()
        pass

    def error_received(self, exc):
        # print('Error received:', exc)
        pass

    def connection_lost(self, exc):
        # print("Connection closed")
        pass


class SyslogServerProtocol(asyncio.DatagramProtocol):
    def __init__(self):
        super().__init__()
        self.transport = None

    def connection_made(self, trans):
        self.transport = trans

    def datagram_received(self, data, addr):
        message = data.decode().strip()
        # print('Received %r from %s' % (message, addr))
        queue_in.put_nowait(message)
        # print('Send %r to %s' % (rs, addr))
        # self.transport.sendto(rs.encode(), addr)


async def send_message(remote, message):
    # on_con_lost = loop.create_future()
    tr, proto = await loop.create_datagram_endpoint(
        lambda: UdpClientProtocol(message, loop),
        remote_addr=(remote[0], remote[1]))
    # await on_con_lost
    # print(tr)
    tr.close()


async def udp_sender(remotes):
    while True:
        message = await queue_out.get()
        for remote in remotes:
            loop.create_task(send_message(remote, message))


async def reformator():
    while True:
        message = await queue_in.get()
        p = message.split()
        l = len(p)
        res = []
        prev = None
        for index, elem in enumerate(p):
            if index > 0:
                prev = p[index - 1]
            if prev in ['machine', 'user', 'User']:
                continue
            res.append(elem)
            if elem == 'machine':
                if index < (l - 1):
                    res.append(p[index + 1])
                    try:
                        resolve = aiodns.DNSResolver()
                        # print('Will query: ', p[index + 1])
                        res.append(
                            '(' + str((await resolve.gethostbyname(p[index + 1], socket.AF_INET)).addresses[0]) + ')')
                        # res.append('(' + dns.resolver.resolve(p[index + 1], 'A')[0].to_text() + ')')
                    except Exception as e:
                        # print('Except', e)
                        pass
            elif elem == 'user' or elem == 'User':
                if index < (l - 1):
                    res.append('[' + p[index + 1] + ']')
        rs = ' '.join(res) + '\n'
        await queue_out.put(rs)


queue_in = asyncio.Queue()
queue_out = asyncio.Queue()

loop = asyncio.get_event_loop()
print("Starting UDP server")
# One protocol instance will be created to serve all client requests
listen = loop.create_datagram_endpoint(
    SyslogServerProtocol, local_addr=('0.0.0.0', 514))

loop.create_task(reformator())
loop.create_task(udp_sender([('127.0.0.1', 9999), ('127.0.0.1', 9998)]))

transport, protocol = loop.run_until_complete(listen)

try:
    loop.run_forever()
except KeyboardInterrupt:
    pass

transport.close()
loop.close()
