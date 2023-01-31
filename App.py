from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
import json
import os
import tkinter as tk  # python 3
from tkinter import font as tkfont, scrolledtext  # python 3
from tkinter import filedialog as fd
from tkinter import *
from tkinter.constants import DISABLED


class DesChipper:
    encryption_key = ""
    encryption_iv = ""

    def __init__(self, key:str, iv:str):
        self.encryption_key = key
        self.encryption_iv = iv

    def encrypt(self, message: str):
        cipher = DES3.new(self.encryption_key.encode(), DES3.MODE_OFB)
        cipher_text = cipher.encrypt(pad(message.encode(), DES3.block_size))
        iv = b64encode(cipher.iv).decode('utf-8')
        ct = b64encode(cipher_text).decode('utf-8')
        result = json.dumps({'iv': iv, 'ciphertext': ct})
        return result

    def decrypt(self, message):
        try:
            cipher = DES3.new(self.encryption_key.encode(), DES3.MODE_OFB, b64decode(self.encryption_iv))
            pt = unpad(cipher.decrypt(b64decode(message)), DES3.block_size)
            return pt.decode()
        except(ValueError, KeyError) as e:
            print(e)
            print("Incorrect decryption")


class SampleApp(tk.Tk):
    file_path: tk.StringVar
    file_data = ""

    def write_to_file(self, file_data: str):
        try:
            file = open(self.file_path.get(), "w", encoding='utf-8')
            file.write(file_data)
            file.close()
            self.file_data = file_data
        except Exception as e:
            print(str(e))

    def __init__(self, *args, **kwargs):
        tk.Tk.__init__(self, *args, **kwargs)
        self.title_font = tkfont.Font(family='Helvetica', size=18, weight="bold", slant="italic")
        self.small_title_font = tkfont.Font(family='Helvetica', size=10, weight="normal", slant="italic")

        # the container is where we'll stack a bunch of frames
        # on top of each other, then the one we want visible
        # will be raised above the others
        container = tk.Frame(self)
        container.pack(side="top", fill="both", expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        self.frames = {}
        for F in (StartPage, EncryptionPage, DecryptionPage):
            page_name = F.__name__
            frame = F(parent=container, controller=self)
            self.frames[page_name] = frame

            # put all of the pages in the same location;
            # the one on the top of the stacking order
            # will be the one that is visible.
            frame.grid(row=0, column=0, sticky="nsew")

        self.show_frame("StartPage")

    def show_frame(self, page_name):
        frame = self.frames[page_name]
        frame.loaded()
        frame.tkraise()


class StartPage(tk.Frame):
    is_valid_path: tk.BooleanVar
    controller: SampleApp
    file_name: tk.StringVar
    encryption_btn: Button
    decryption_btn: Button

    def pick_file(self, event):
        file_path = fd.askopenfilename(
            title="Оберіть файл",
            filetypes=(("Text Files", "*.txt"),)
        )
        try:
            file = open(file_path, encoding="utf-8")
            self.controller.file_data = file.read()
            file.close()
            self.file_name.set(os.path.basename(file_path))
            self.controller.file_path.set(file_path)
            self.is_valid_path.set(True)
        except Exception as e:
            print(str(e))
            self.is_valid_path.set(False)
        return

    def is_valid_path_updated(self, sv):
        buttons_state = tk.NORMAL if sv.get() else tk.DISABLED
        self.encryption_btn['state'] = buttons_state
        self.decryption_btn['state'] = buttons_state

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.is_valid_path = tk.BooleanVar()
        self.file_name = tk.StringVar()
        self.controller.file_path = tk.StringVar()
        self.is_valid_path.trace("w", lambda name, index, mode, sv=self.is_valid_path: self.is_valid_path_updated(sv))
        frame = tk.Frame(self)
        label = tk.Label(self, text="Welcome to files encryptor", font=controller.title_font, bg='#ffb700')
        label.pack(side="top", fill="x", pady=30)
        file_label = tk.Label(frame, text="Назва файлу:", font=controller.small_title_font)
        file_label.grid(row=0, column=0, padx=5, pady=20)
        file_input = tk.Entry(frame, textvariable=self.file_name)
        file_input.bind("<Button-1>", self.pick_file)
        file_input.grid(row=0, column=1, padx=5, pady=20)
        self.encryption_btn = tk.Button(frame, text="До шифрування", state=DISABLED, command=lambda: controller.show_frame("EncryptionPage"))
        self.encryption_btn.grid(row=1, column=0, padx=5, pady=5)
        self.decryption_btn = tk.Button(frame, text="До дешифрування", state=DISABLED, command=lambda: controller.show_frame("DecryptionPage"))
        self.decryption_btn.grid(row=1, column=1, padx=5, pady=5)
        frame.pack()

    def loaded(self):
        pass


class EncryptionPage(tk.Frame):
    controller: SampleApp
    file_content_area: scrolledtext.ScrolledText
    encryption_key: StringVar
    encryption_iv: StringVar

    def start_encrypt(self):
        chipper = DesChipper(self.encryption_key.get(), self.encryption_iv.get())
        json_result = chipper.encrypt(self.controller.file_data)
        b64 = json.loads(json_result)
        self.controller.write_to_file(b64['ciphertext'])
        self.file_content_area.delete('1.0', END)
        self.file_content_area.insert(END, b64['ciphertext'])
        self.encryption_iv.set(b64['iv'])

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.encryption_key = StringVar()
        self.encryption_iv = StringVar()
        settings_frame = tk.Frame(self)
        data_frame = tk.Frame(self)
        buttons_frame = tk.Frame(self)
        # data_frame items
        label = tk.Label(data_frame, text="Ширування документу", font=controller.title_font)
        label.grid(row=0, column=0, pady=10)
        self.file_content_area = scrolledtext.ScrolledText(data_frame, undo=True, height=15)
        self.file_content_area.insert(END, "")
        self.file_content_area.grid(row=1, column=0)
        # buttons_frame items
        button = tk.Button(buttons_frame, text="На головну", command=lambda: controller.show_frame("StartPage"), width=15)
        button.grid(row=0)
        button = tk.Button(buttons_frame, text="Шифрувати", command=lambda: self.start_encrypt(), width=15)
        button.grid(row=1)
        # settings_frame items
        key_label = tk.Label(settings_frame, text="Парольна фраза:", font=controller.small_title_font)
        key_label.grid(row=3, column=0, padx=5, pady=5)
        key_input = tk.Entry(settings_frame, textvariable=self.encryption_key, width=50)
        key_input.grid(row=3, column=1, padx=5, pady=5)

        iv_label = tk.Label(settings_frame, text="Згенерований iv:", font=controller.small_title_font)
        iv_label.grid(row=4, column=0, padx=5, pady=5)
        iv_input = tk.Entry(settings_frame, textvariable=self.encryption_iv, width=50)
        iv_input.grid(row=4, column=1, padx=5, pady=5)
        #
        data_frame.grid(row=0)
        buttons_frame.grid(row=0, column=1)
        settings_frame.grid(row=1)

    def loaded(self):
        self.file_content_area.delete('1.0', END)
        self.file_content_area.insert(END, self.controller.file_data)


class DecryptionPage(tk.Frame):
    controller: SampleApp
    file_content_area: scrolledtext.ScrolledText
    encryption_key: StringVar
    encryption_iv: StringVar

    def start_decrypt(self):
        chipper = DesChipper(self.encryption_key.get(), self.encryption_iv.get())
        decrypted_text = chipper.decrypt(self.controller.file_data)
        self.controller.write_to_file(decrypted_text)
        self.file_content_area.delete('1.0', END)
        self.file_content_area.insert(END, decrypted_text)

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.encryption_key = StringVar()
        self.encryption_iv = StringVar()
        settings_frame = tk.Frame(self)
        data_frame = tk.Frame(self)
        buttons_frame = tk.Frame(self)
        # data_frame items
        label = tk.Label(data_frame, text="Деширування документу", font=controller.title_font)
        label.grid(row=0, column=0, pady=10)
        self.file_content_area = scrolledtext.ScrolledText(data_frame, undo=True, height=15)
        self.file_content_area.insert(END, "")
        self.file_content_area.grid(row=1, column=0)
        # buttons_frame items
        button = tk.Button(buttons_frame, text="На головну", command=lambda: controller.show_frame("StartPage"), width=15)
        button.grid(row=0)
        button = tk.Button(buttons_frame, text="Дешифрувати", command=lambda: self.start_decrypt(), width=15)
        button.grid(row=1)
        # settings_frame items
        key_label = tk.Label(settings_frame, text="Парольна фраза:", font=controller.small_title_font)
        key_label.grid(row=3, column=0, padx=5, pady=5)
        key_input = tk.Entry(settings_frame, textvariable=self.encryption_key, width=50)
        key_input.grid(row=3, column=1, padx=5, pady=5)

        iv_label = tk.Label(settings_frame, text="iv:", font=controller.small_title_font)
        iv_label.grid(row=4, column=0, padx=5, pady=5)
        iv_input = tk.Entry(settings_frame, textvariable=self.encryption_iv, width=50)
        iv_input.grid(row=4, column=1, padx=5, pady=5)
        #
        data_frame.grid(row=0)
        buttons_frame.grid(row=0, column=1)
        settings_frame.grid(row=1)

    def loaded(self):
        self.file_content_area.delete('1.0', END)
        self.file_content_area.insert(END, self.controller.file_data)
        pass


if __name__ == "__main__":
    app = SampleApp()
    app.title('Files_Encryptor')
    app.resizable(width=False, height=False)
    app.mainloop()
