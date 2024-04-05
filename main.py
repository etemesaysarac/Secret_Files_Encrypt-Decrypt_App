import tkinter
from tkinter import *
from tkinter import messagebox
from tkinter import ttk
import base64

def encode(key,clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c))%256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode(''.join(enc).encode()).decode()

def decode(key,enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return ''.join(dec)

def save_and_encrypt_notes():
    title = entry_title.get()
    message = text.get('1.0',END)
    master_secret = entry_masterkey.get()

    if len(title) == 0 or len(message) == 0 or len(master_secret) == 0:
        messagebox.showinfo(title='Error!', message='Please Enter all info CORRECTLY!')
    else:
        message_encrypted = encode(master_secret,message)

        try:
            with open('MyTopSecret.txt','a') as data_file:
                data_file.write(f'\n{title}\n{message_encrypted}')
        except FileNotFoundError:
            with open('MyTopSecret.txt','w') as data_file:
                data_file.write(f'\n{title}\n{message_encrypted}')
        finally:
            entry_title.delete(0,END)
            entry_masterkey.delete(0,END)
            text.delete('1.0',END)
def decrypt_notes():
    message_encrypted = text.get('1.0',END)
    master_secret = entry_masterkey.get()

    if len(message_encrypted) == 0 or len(master_secret) == 0:
        messagebox.showinfo(title='Error!', message='Please Enter all info CORRECTLY!')
    else:
        try:
            decrypted_message = decode(master_secret,message_encrypted)
            text.delete('1.0',END)
            text.insert('1.0',decrypted_message)
        except:
            messagebox.showinfo(title='ERROR!', message='Please Enter ENCRYPTED Text!')

window = Tk()
window.title('Secret Notes')
window.iconbitmap('image.ico')
window.minsize(width=500, height=500)
window.config(padx=20, pady=20)

image = tkinter.PhotoImage(file="image1.png", width=100, height=100)
label_image = ttk.Label(image=image)
label_image.pack()

label_title = Label(window, text='Enter your Title')
label_title.config(pady=5)
label_title.pack()
entry_title = Entry()
entry_title.focus()
entry_title.pack()

label_text = Label(window, text='Enter your Secret')
label_text.pack()
label_text.config(pady=5)
text = Text(width=30, height=10)
text.pack()

label_masterkey = Label(window, text='Enter Master Key')
label_masterkey.pack()
label_masterkey.config(pady=5)
entry_masterkey = Entry()
entry_masterkey.pack()

button_save = Button(text='Save & Encrypt', command=save_and_encrypt_notes)
button_save.pack()

button_save = Button(text='Decrypt', command=decrypt_notes)
button_save.pack()

window.mainloop()
