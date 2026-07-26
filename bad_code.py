import os

def execute_command(user_input):
    # This is highly vulnerable to command injection!
    os.system(user_input)
