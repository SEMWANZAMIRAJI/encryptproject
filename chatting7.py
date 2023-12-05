import tkinter as tk
from hashlib import sha256

def encrypt_message():
    message = entry_message.get()
    key = entry_key.get()

# Encrypt the message (using a simple XOR encryption for demonstration)
    encrypted_message = ''.join(chr(ord(c) ^ ord(key)) for c in message)

# Add authentication factor (SHA256 hash)
    hashed_message = sha256(encrypted_message.encode()).hexdigest()
    authenticated_message = f"{encrypted_message}+{hashed_message}"

# Update label to show the encrypted message (ciphertext)
    label_ciphertext.config(text=f"Ciphertext: {authenticated_message}")

def verify_and_decrypt():
    received_message = entry_received.get()
    received_parts = received_message.split('+')

    if len(received_parts) == 2:
     encrypted_message, received_hash = received_parts

# Decrypt the message using the key
    decrypted_message = ''.join(chr(ord(c) ^ ord(entry_key_receiver.get())) for c in encrypted_message)

# Verify the received message's integrity
    calculated_hash = sha256(encrypted_message.encode()).hexdigest()

    if calculated_hash == received_hash:
        label_authentication.config(text="Authenticated")
        label_decrypted_message.config(text=f"Decrypted message: {decrypted_message}")
    else:
        label_authentication.config(text="Not Authenticated")
        label_decrypted_message.config(text="")

# Sender interface
    sender_window = tk.Tk()
    sender_window.title("Sender Interface")

    label_message = tk.Label(sender_window, text="Enter message:")
    label_message.pack()

    entry_message = tk.Entry(sender_window)
    entry_message.pack()

    label_key = tk.Label(sender_window, text="Enter key:")
    label_key.pack()

    entry_key = tk.Entry(sender_window)
    entry_key.pack()

    button_encrypt = tk.Button(sender_window, text="Encrypt Message", command=encrypt_message)
    button_encrypt.pack()

    label_ciphertext = tk.Label(sender_window, text="Ciphertext will appear here")
    label_ciphertext.pack()

    sender_window.mainloop()


# Receiver interface
receiver_window = tk.Tk()
receiver_window.title("Receiver Interface")

label_received = tk.Label(receiver_window, text="Enter received ciphertext:")
label_received.pack()

entry_received = tk.Entry(receiver_window)
entry_received.pack()

label_key_receiver = tk.Label(receiver_window, text="Enter key:")
label_key_receiver.pack()

entry_key_receiver = tk.Entry(receiver_window)
entry_key_receiver.pack()

button_verify_decrypt = tk.Button(receiver_window, text="Verify & Decrypt", command=verify_and_decrypt)
button_verify_decrypt.pack()

label_authentication = tk.Label(receiver_window, text="")
label_authentication.pack()

label_decrypted_message = tk.Label(receiver_window, text="")
label_decrypted_message.pack()

receiver_window.mainloop()
