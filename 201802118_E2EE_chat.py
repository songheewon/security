from socket import *
import threading
from Cryptodome import Random
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from tkinter import *

class E2EE_Chat:
    def __init__(self):
        self.HOST = "homework.islab.work"
        self.PORT_NUM = 8080
        self.clientSock = socket(AF_INET, SOCK_STREAM)
        self.clientSock.connect((self.HOST, self.PORT_NUM))
        self.BS = 16
        self.pad = lambda s: s + (BS - len(s.encode('utf-8')) % BS) * chr(BS - len(s.encode('utf-8')) % BS)
        self.unpad = lambda s : s[:-ord(s[len(s)-1:])]

        # set public key and private key
        self.random_generator = Random.new().read
        self.key_length = 2048
        self.key_pair = RSA.generate(self.key_length, self.random_generator)
        self.pub_key = self.key_pair.publickey()
        self.pri_key = self.key_pair.export_key()

        self.window=Tk()
        self.window.title("E2EE Chat Program")
        self.window.geometry("640x380+200+100")
        self.window.resizable(False, False)
        server_label = Label(self.window, text="Server")
        server_label.place(x=20, y=30)
        self.server_entry = Entry(self.window, width=50, text="")
        self.server_entry.place(x=100, y=30)
        port_label = Label(self.window, text="Port")
        port_label.place(x=20, y=60)
        self.port_entry = Entry(self.window, width=50, text="")
        self.port_entry.place(x=100, y=60)
        self.connect_button = Button(self.window, overrelief="ridge", borderwidth=3, padx=10, pady=10, text="CONNECT/DISCONNECT",
                                     command=self.connect_or_not)
        self.connect_button.place(x=460, y=30)
        self.connection = Label(self.window, text="")
        self.connection.place(x=100, y=3)
        self.msg_to_send = Text(self.window, height=7, width=85)
        self.msg_to_send.place(x=20, y=90)
        self.send_button = Button(self.window, overrelief="ridge", borderwidth=3, padx=380, pady=10, text="SEND")
        self.send_button.place(x=0, y=200, relwidth=1)
        self.msg_received = Text(self.window, height=7, width=85)
        self.msg_received.place(x=20, y=260)
        self.window.mainloop()

        self.new_window = None
        self.name_text = Entry()
        self.credential_confirm = Button()
        self.name=""
        self.connected_flag = False

    def Encrypt(self, raw, key, iv):
        raw = pad(raw)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return b64encode(iv + cipher.Encrypt(raw.encode('utf-8')))

    def EncryptMsg(self, raw, key, iv):
        return Encrypt(raw, key, iv).decode('utf-8')

    def Decrypt(self, enc, key):
        enc = b64decode(enc)
        iv = enc[:16]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.Decrypt(enc[16:]))

    def DecryptMsg(self, enc, key):
        if type(enc) == str:
            enc = str.encode(enc)
        return Decrypt(enc, key).decode('utf-8')

    def socket_read(self):
        while True:
            readbuff = connectSocket.recv(2048)
            if len(readbuff) == 0:
                continue
            recv_payload = readbuff.decode('utf-8')
            parse_payload(recv_payload)

    def socket_send(self):
        while True:
            str = input("MESSAGE: ")
            send_bytes = str.encode('utf-8')
            connectSocket.sendall(send_bytes)

    def parse_payload(self, payload):
        print(payload)
        str_list = payload.split("\n")
        print(str_list)
        pass

    def connect_or_not(self):
        if not self.connected_flag:
            self.write_name()
        else:
            self.disconnect()

    def disconnect(self):
        self.connection.config(fg="red", text="3EPROTO DISCONNECT")

    def write_name(self):
        self.new_window=Toplevel()
        self.new_window.title("CREDENTIAL SETTING")
        self.new_window.resizable(False, False)
        self.new_window.geometry("400x100+300+200")
        self.name_text=Entry(self.new_window, width=53, text="")
        self.name_text.place(x=10, y=30)
        self.credential_confirm=Button(self.new_window, overrelief="ridge", borderwidth=3, padx=50, pady=5, text="OK", command=self.credential_chk)
        self.credential_confirm.place(x=130, y=55)

    def credential_chk(self):
        self.new_window.destroy()
        self.connection.config(fg="blue", text="3EPROTO CONNECT")
    #reading_thread = threading.Thread(target=socket_read)
    #sending_thread = threading.Thread(target=socket_send)
chat=E2EE_Chat()
    #reading_thread.start()
    #sending_thread.start()

    #reading_thread.join()
    #sending_thread.join()