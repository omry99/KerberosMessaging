import logging
from messaging_server import MessagingServer

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')


def main():
    messaging_server = MessagingServer()
    messaging_server.serve()


if __name__ == '__main__':
    main()
