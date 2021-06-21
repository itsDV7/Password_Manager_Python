import os
import json
import base64
import binascii
from pwdgen import generate_password
from collections import defaultdict
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

global fernet_key


def addPassword():
    global fernet_key
    website = input("Enter Website: ")
    username = input("Enter Username: ")
    password = input("Enter Password (Press ENTER to Generate Password): ")
    if password == "":
        password = generate_password(pwd_length=32, no_numbers=False, no_special_chars=False, print_pwd=False)
        print("Generated Password: {}\n".format(password))
    dictionary = {website: [username, password]}
    dict_to_json = json.dumps(dictionary).encode('utf-8')
    tokenEncrypt = fernet_key.encrypt(dict_to_json).decode('utf-8')
    file = open("database.encrypted", 'a')
    file.write(tokenEncrypt+"\n")
    file.close()
    print("Successfully Added")


def updatePassword():
    global fernet_key
    dataUpdated = False
    data_dictionary = defaultdict(list)
    os.system("attrib -h database.encrypted")
    with open("database.encrypted", 'r') as database:
        for line in database.readlines():
            tokenDecrypt = json.loads(fernet_key.decrypt(line.encode('utf-8')).decode('utf-8'))
            for key, value in tokenDecrypt.items():
                data_dictionary[key].append(value)
        website = input("Enter Website: ")
        username = input("Enter Username: ")
        if website in data_dictionary.keys():
            for index, users in enumerate(data_dictionary.get(website)):
                if users[0] == username:
                    updatedPassword = input("Enter New Password (Press ENTER to Generate Password): ")
                    if updatedPassword == "":
                        updatedPassword = generate_password(pwd_length=32, no_numbers=False, no_special_chars=False,
                                                            print_pwd=False)
                        print("Generated Password: {}\n".format(updatedPassword))
                    data_dictionary.get(website)[index][1] = updatedPassword
                    dataUpdated = True
                    print("Password Updated...")
                    break
            else:
                print("User Data Not Found!")
        else:
            print("Website Not Found!")
        database.close()
        if dataUpdated:
            with open("database.encrypted", 'w') as database:
                for website, users in data_dictionary.items():
                    for user in users:
                        dictionary = {website: user}
                        dict_to_json = json.dumps(dictionary).encode('utf-8')
                        tokenEncrypt = fernet_key.encrypt(dict_to_json).decode('utf-8')
                        database.write(tokenEncrypt+"\n")
        os.system("attrib +h database.encrypted")
        database.close()


def removePassword():
    global fernet_key
    dataUpdated = False
    data_dictionary = defaultdict(list)
    os.system("attrib -h database.encrypted")
    with open("database.encrypted", 'r') as database:
        for line in database.readlines():
            tokenDecrypt = json.loads(fernet_key.decrypt(line.encode('utf-8')).decode('utf-8'))
            for key, value in tokenDecrypt.items():
                data_dictionary[key].append(value)
        website = input("Enter Website: ")
        username = input("Enter Username: ")
        if website in data_dictionary.keys():
            for index, users in enumerate(data_dictionary.get(website)):
                if users[0] == username:
                    data_dictionary.get(website).remove(data_dictionary.get(website)[index])
                    dataUpdated = True
                    print("User Data Successfully Deleted...")
                    break
            else:
                print("User Data Not Found!")
        else:
            print("Website Not Found!")
        database.close()
        if dataUpdated:
            with open("database.encrypted", 'w') as database:
                for website, users in data_dictionary.items():
                    for user in users:
                        dictionary = {website: user}
                        dict_to_json = json.dumps(dictionary).encode('utf-8')
                        tokenEncrypt = fernet_key.encrypt(dict_to_json).decode('utf-8')
                        database.write(tokenEncrypt+"\n")
        os.system("attrib +h database.encrypted")
        database.close()


def viewPassword():
    global fernet_key
    print("{:<30}{:<30}{:<30}".format("WEBSITE", "USERNAME", "PASSWORD"))
    print("{:<30}{:<30}{:<30}".format("-"*30, "-"*30, "-"*30))
    data_dictionary = defaultdict(list)
    with open("database.encrypted", 'r') as database:
        for line in database.readlines():
            tokenDecrypt = json.loads(fernet_key.decrypt(line.encode('utf-8')).decode('utf-8'))
            for key, value in tokenDecrypt.items():
                data_dictionary[key].append(value)
        for key in sorted(data_dictionary, key=data_dictionary.get, reverse=False):
            for value in data_dictionary[key]:
                print("{:<30}{:<30}{:<30}".format(key, value[0], value[1]))
        database.close()


def changeMasterPassword():
    global fernet_key
    newPassword = input("Enter New Password: ").encode('utf-8')
    print("Creating New Verification...")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=newPassword,
        iterations=100000
    )
    newPassword_key = base64.urlsafe_b64encode(kdf.derive(key_material=newPassword))
    print("Save this KEY in-case you forget Master Password >> {}".format(newPassword_key.decode('utf-8')))
    newFernet_key = Fernet(newPassword_key)
    verifyFile = open("verify.verify", 'r')
    verifyToken = fernet_key.decrypt(verifyFile.readline().encode('utf-8')).decode('utf-8')
    verifyFile.close()
    verifyToken = newFernet_key.encrypt(verifyToken.encode('utf-8')).decode('utf-8')
    verifyFile = open("verify.verify", 'w')
    verifyFile.write(verifyToken)
    verifyFile.close()

    print("Re-Encrypting Database...")
    os.system("attrib -h database.encrypted")
    with open("database.encrypted", 'r') as database:
        lines = [newFernet_key.encrypt(fernet_key.decrypt(line.encode('utf-8'))).decode('utf-8')
                 for line in database.readlines()]
        database.close()

    with open("database.encrypted", 'w') as database:
        for line in lines:
            database.write(line+"\n")
        database.close()

    fernet_key = newFernet_key
    os.system("attrib +h database.encrypted")
    print("Master Key Changed Successfully!")
    pass


def forgetMasterPassword():
    global fernet_key
    recoveryKey = input("Please enter your Recovery Key >> ")
    try:
        testFernet_key = Fernet(recoveryKey.encode('utf-8'))
        verifyFile = open("verify.verify", 'r')
        verifyToken = verifyFile.readline().encode('utf-8')
        testFernet_key.decrypt(verifyToken)
        verifyFile.close()
        print("Recovery Key Verified!")
        fernet_key = testFernet_key
        changeMasterPassword()
    except (binascii.Error, InvalidToken):
        deleteData = input("""
                Invalid Recovery Key!

                If you don't have your recovery key, you will have to delete your complete database to continue using this
                program.

                If you wish to continue, please enter CONTINUE >> 
                """)
        if deleteData == "CONTINUE":
            os.remove("database.encrypted")
            print("""
                    Database Deleted!
                    Re-run program to continue...
                    """)



def menu():
    switch = {
        1: addPassword,
        2: updatePassword,
        3: removePassword,
        4: viewPassword,
        5: changeMasterPassword
    }
    while True:
        print("""
        1. Add Password
        2. Update Password
        3. Remove Password
        4. View Database
        5. Change Master Password
        6. Exit
        """)
        try:
            choice = int(input(">> "))
            if choice == 6:
                print("Exiting...")
                break
            else:
                func = switch.get(choice, lambda: print("Incorrect Input"))
                func()
        except ValueError:
            print("Invalid Input")


def main():
    global fernet_key
    print("""
 _____                             ______                                   _    ___  ___                                  
/  ___|                            | ___ \                                 | |   |  \/  |                                  
\ `--.  ___  ___ _   _ _ __ ___    | |_/ /_ _ ___ _____      _____  _ __ __| |   | .  . | __ _ _ __   __ _  __ _  ___ _ __ 
 `--. \/ _ \/ __| | | | '__/ _ \   |  __/ _` / __/ __\ \ /\ / / _ \| '__/ _` |   | |\/| |/ _` | '_ \ / _` |/ _` |/ _ \ '__|
/\__/ /  __/ (__| |_| | | |  __/   | | | (_| \__ \__ \\\ V  V / (_) | | | (_| |   | |  | | (_| | | | | (_| | (_| |  __/ |   
\____/ \___|\___|\__,_|_|  \___|   \_|  \__,_|___/___/ \_/\_/ \___/|_|  \__,_|   \_|  |_/\__,_|_| |_|\__,_|\__, |\___|_|   
                                                                                                            __/ |          
                                                                                                           |___/           
    
                       ....                       
              .......................             
          ...............................         
       ....................................       
     .........................................    
    ........       ..         ..       ........   
  ..........                           .........  
  ..........                           .......... 
 .........                               .........
 .........   https://github.com/itsDV7    .........
..........                               .........
 .........                               .........
 ..........                             ..........
  ...........                         ........... 
   ....   .......                 ..............  
    .....   ........           ................   
     ......     .               .............     
        .....                   ...........       
          .........             ........          
               ....             ....              
                   
    """)
    if os.path.exists("database.encrypted"):
        print("Existing Database Found...\n")
        password_master = input("Enter Master Password >> ").encode('utf-8')
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=password_master,
            iterations=100000
        )
        password_key = base64.urlsafe_b64encode(kdf.derive(key_material=password_master))
        fernet_key = Fernet(password_key)
        verifyFile = open("verify.verify", 'r')
        verifyKey = verifyFile.readline().encode('utf-8')
        try:
            fernet_key.decrypt(verifyKey)
            verifyFile.close()
            menu()
        except InvalidToken:
            verifyFile.close()
            print("Invalid Master Password!")
            choice = input("Forgot your Master Password? Y/N >> ")
            if choice in ['Y', 'y', 'Yes', 'yes']:
                forgetMasterPassword()
            print("Exiting...")
    else:
        password_master = input("Enter New Master Password >> ").encode('utf-8')
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=password_master,
            iterations=100000
        )
        password_key = base64.urlsafe_b64encode(kdf.derive(key_material=password_master))
        fernet_key = Fernet(password_key)
        verifyToken = fernet_key.encrypt(b"Key Validation Encryption").decode('utf-8')
        file = open("verify.verify", 'w')
        file.write(verifyToken)
        file.close()
        print("Save this KEY in-case you forget Master Password >> {}".format(password_key.decode('utf-8')))
        print("Creating new Database...\n")
        file = open("database.encrypted", 'w')
        os.system("attrib +h database.encrypted")
        file.close()
        menu()


if __name__ == "__main__":
    main()
