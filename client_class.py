"""
@author:    Talha Sezer Çakır
@id:        150180027
@detail:    BLG433E HW1
"""

import socket
import hashlib
import threading
import enum
import time


class EventStatus(enum.Enum):
    success = 0
    failure = 1


class ServerPackets(enum.IntEnum):
    Information = 0,
    Question = 1,
    Letter = 2,
    Time = 3,
    EndGame = 4


class ClientPackets(enum.IntEnum):
    StartGame = 0,
    TerminateGame = 1,
    FetchNextQuestion = 2,
    BuyLetter = 3,
    Guess = 4,
    GetRemTime = 5


class EncodingType(enum.IntEnum):
    UTF_8 = 0,
    UTF_16 = 1


class Socket:

    def __init__(self, host, port) -> None:
        """
        :param  host:   IP adress of server
        :param port:    Port number of server
        """
        self.host = host
        self.port = port
        self.my_hex = '22712946ACD3DFDC30C2196726F8B943'
        self.terminate_game = False
        self.terminate_threads = False
        self.question_num = 0
        self.overall_score = None
        self.rem_time = None
        self.rem_time_counter = 0
        self.inf_msg_flag = True
        self.get_rem_time_flag = False
        # tcp socket of client side
        self.client_socket = None

    def open(self):
        """
        The open function initialize the socket and connect socket to server.
        """
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((self.host, self.port))
        self.authenticate()

    def authenticate(self):
        """
        Authentication part of the homework. TCP connection is established
        accoring to PDF.
        """

        self.client_socket.sendall(b"Start_Connection")

        random_hex = self.client_socket.recv(1024).decode()
        hex_str = random_hex + self.my_hex
        final_hex_str = hashlib.sha1(hex_str.encode()).hexdigest()
        authentication_arr = "#".join([final_hex_str, "150180027"])

        self.client_socket.sendall(authentication_arr.encode())
        message = self.client_socket.recv(512).decode()

        y_or_n = input(message)
        self.client_socket.sendall(y_or_n.encode())

    def start_game(self):
        """
        The game starts in here. Multithreading is applied to communicate
        with server for sending and receiving packets.


        """

        print("Game starts now...\n")
        print("The instructions may be as follows.\n\n \
                0: Start Game\n \
                1: Terminate the game\n \
                2: Fetch the next question\n \
                3: Buy a letter\n \
                4: Take a guess\n \
                5: Get rem. time\n\n")

        self.client_socket.sendall(ClientPackets.StartGame.to_bytes(1, 'little'))

        # asynchronous communication for sending and receiving
        t_rec = threading.Thread(target=self.game_receive)
        t_send = threading.Thread(target=self.game_send)

        t_rec.start()
        time.sleep(1)
        # game_send thread is configured as Daemon thread because
        # first receive operation ends. send thread terminate itself
        # when the game_receive thread stops.
        t_send.setDaemon(True)
        t_send.start()

        # run game until the first thread(game_receive) terminates
        while not self.terminate_threads:
            continue

        # game_receive joins to main thread.
        # game_send thread terminates itself in here due to the Daemo feature.
        t_rec.join()

        print("Game is over. Remaining time {} and overall score {}"
              .format(self.rem_time, self.overall_score))

    def game_send(self):
        """
        Second thread, it sends the user inputs as packets to server.
        """

        while not self.terminate_game:

            inst_input = int(input(str("Enter your instruction as integer value: \n")))
            if inst_input == ClientPackets.Guess:
                guess = input(str("Enter your word guess: "))
                inst_input = str(inst_input) + guess
                self.client_socket.sendall(inst_input.encode())
            elif inst_input == ClientPackets.GetRemTime:
                self.get_rem_time_flag = True
            else:
                self.client_socket.sendall(inst_input.to_bytes(1, 'little'))

    def game_receive(self):
        """
        First thread of the game. It listens to server and parses the packets
        if packets appropriate with the descriptions.

        When terminate game input come from user it first termiante the game with
        updating terminate_game flag inside the parse_server_packets function then
        it goes out the while loop that receiving operations are done. Finally threads
        terminates with updating terminate_threads flag as True.
        """

        while not self.terminate_game:
            recv_msg = self.client_socket.recv(2048)

            if not (recv_msg and (recv_msg[0] in ServerPackets.__members__.values())):
                continue
            self.parse_server_packets(packet=recv_msg)

        self.terminate_threads = True

    def parse_server_packets(self, packet):
        """
        :param packet:  Receiving packet from server, size and content of it
                        depends on the user input.

        it splits the packet content depends on it packet type for each received message.
        """

        packet_type = packet[0]

        if packet_type == ServerPackets.Information:
            inf_message = "N/A"
            enc_type = packet[1]
            size_payload = int.from_bytes(packet[2:4], "little")
            payload = packet[4:]

            if enc_type == EncodingType.UTF_8:
                inf_message = payload.decode('utf-8')
            elif enc_type == EncodingType.UTF_16:
                inf_message = payload.decode('utf-16le')

            # show one time inf message to user
            if self.inf_msg_flag:
                print("Information message from server is {}\n".format(inf_message))
                self.inf_msg_flag = False

            time.sleep(2)

        elif packet_type == ServerPackets.Question:
            self.question_num += 1
            question_text = "N/A"

            enc_type = packet[1]
            size_payload = int.from_bytes(packet[2:4], "little")
            word_lenght = int.from_bytes(packet[4:6], "little")
            payload = packet[6:6 + size_payload]

            if enc_type == EncodingType.UTF_8:
                question_text = payload.decode('utf-8')
            elif enc_type == EncodingType.UTF_16:
                question_text = payload.decode('utf-16')

            print("Word lenght is {} letters. The question {} is here ->\t\t{}\n"
                  .format(word_lenght, self.question_num, question_text))
            time.sleep(4)

        elif packet_type == ServerPackets.Letter:
            pos_of_letter = packet[2]
            letter = packet[3:4].decode('utf-8')
            print("Letter bought is {} and position of it is {} in the word".format(letter, pos_of_letter))

        elif packet_type == ServerPackets.Time:
            rem_time_sec = int.from_bytes(packet[4:6], "little")
            self.rem_time_counter += 1
            # show remaining time every 15 times
            if self.rem_time_counter % 15 == 0 or self.get_rem_time_flag:
                print("Remaining time is {}\n".format(rem_time_sec))
                self.get_rem_time_flag = False

        elif packet_type == ServerPackets.EndGame:
            self.overall_score = int.from_bytes(packet[2:4], "little")
            self.rem_time = int.from_bytes(packet[4:6], "little")
            # endgame controller
            self.terminate_game = True


def main():
    tcp_socket = Socket('160.75.154.126', 2022)
    tcp_socket.open()
    tcp_socket.start_game()


if __name__ == "__main__":
    main()
