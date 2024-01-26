import logging
from file_server import FileServer

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')


def main():
    import os
    os.system("del defensive.db /f")
    os.system(
        'del \"D:\\Files\\University\\מבוא לאבטחת המרחב המקוון\\ממן 16\\KerberosMessaging\\Client\\Client\\me.info\" /f')

    file_server = FileServer()
    file_server.serve()


if __name__ == '__main__':
    main()
