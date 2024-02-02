import logging
from authentication_server import AuthenticationServer

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')


def main():
    import os
    os.system("del clients /f")
    os.system(
         'del \"D:\\Files\\University\\מבוא לאבטחת המרחב המקוון\\ממן 16\\KerberosMessaging\\Client\\Client\\me.info\" /f')

    authenticaion_server = AuthenticationServer()
    authenticaion_server.serve()


if __name__ == '__main__':
    main()
