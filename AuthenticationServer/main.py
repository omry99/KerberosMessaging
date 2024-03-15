import logging
from authentication_server import AuthenticationServer

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')


def main():
    authenticaion_server = AuthenticationServer()
    authenticaion_server.serve()


if __name__ == '__main__':
    main()
