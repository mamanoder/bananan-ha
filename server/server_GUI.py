import tkinter as tk
from threading import Thread
from queue import Queue

class ChatWindow:
    def __init__(self, master, message_queue):
        self.master = master
        self.message_queue = message_queue
        master.title("Chat Window")
        master.geometry("400x300")

        self.message_frame = tk.Frame(master)
        self.message_frame.pack(fill=tk.BOTH, expand=True)

        self.messages_text = tk.Text(self.message_frame, bg="black", fg="white")
        self.messages_text.pack(fill=tk.BOTH, expand=True)

        self.input_frame = tk.Frame(master, bg="black")
        self.input_frame.pack(fill=tk.BOTH)

        self.input_entry = tk.Entry(self.input_frame, bg="black", fg="white")
        self.input_entry.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.send_button = tk.Button(self.input_frame, text="Send", bg="black", fg="white", command=self.send_message)
        self.send_button.pack(side=tk.RIGHT)

        # Start listening for messages
        self.listen_for_messages()

    def send_message(self):
        message = self.input_entry.get()
        self.input_entry.delete(0, tk.END)
        self.display_message("You: " + message)

        # Put the message into the queue
        self.message_queue.put(message)

    def display_message(self, message):
        self.messages_text.insert(tk.END, message + "\n")
        self.messages_text.see(tk.END)  # Scroll to the end of the messages

    def listen_for_messages(self):
        # Continuously check for messages in the queue and display them
        while True:
            if not self.message_queue.empty():
                message = self.message_queue.get()
                self.display_message("Friend: " + message)



message_queue = Queue()


def display_message_on_chat(caller, message):
    """
    Displays a message on the chat window.

    Args:
    - message: The message to be displayed.
    """
    send_message_to_chat(f"{caller}: {message}")


def start_gui_in_thread():
    root = tk.Tk()
    root.mainloop()

# Create a message queue

# Start the GUI in a separate thread


# Function to send a message from other modules
def send_message_to_chat(message, message_queue=message_queue):
    message_queue.put(message)
