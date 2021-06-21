import argparse
import string
from random import randint, choice


def generate_password(pwd_length=16,
                      no_numbers=False,
                      no_special_chars=False,
                      custom_special_chars=list(string.punctuation),
                      print_pwd=False):

    letters = list(string.ascii_letters)
    digits = list(string.digits)
    sp_chars = custom_special_chars
    password = ""
    if no_numbers and no_special_chars:
        for _ in range(pwd_length):
            selection = letters
            password += selection[randint(0, len(selection) - 1)]
    elif no_numbers:
        for _ in range(pwd_length):
            selection = choice([letters, sp_chars])
            password += selection[randint(0, len(selection) - 1)]
    elif no_special_chars:
        for _ in range(pwd_length):
            selection = choice([letters, digits])
            password += selection[randint(0, len(selection) - 1)]
    elif not no_numbers and not no_special_chars:
        for _ in range(pwd_length):
            selection = choice([letters, digits, sp_chars])
            password += selection[randint(0, len(selection) - 1)]
    if print_pwd:
        print("Generated Password: {}".format(password))
    else:
        return password


def main():
    global args
    description = '''
    SECURE PASSWORD GENERATOR
    by - 

     /$$   /$$              /$$$$$$$  /$$    /$$ /$$$$$$$$
    |__/  | $$             | $$__  $$| $$   | $$|_____ $$/
     /$$ /$$$$$$   /$$$$$$$| $$  \ $$| $$   | $$     /$$/ 
    | $$|_  $$_/  /$$_____/| $$  | $$|  $$ / $$/    /$$/  
    | $$  | $$   |  $$$$$$ | $$  | $$ \  $$ $$/    /$$/   
    | $$  | $$ /$$\____  $$| $$  | $$  \  $$$/    /$$/    
    | $$  |  $$$$//$$$$$$$/| $$$$$$$/   \  $/    /$$/     
    |__/   \___/ |_______/ |_______/     \_/    |__/      
    '''
    epilog = '''
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
    '''

    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter, description=description,
                                     epilog=epilog)
    parser.add_argument("-l", "--pwd_length", metavar='', type=int, help="Input Length of Generated Password.",
                        default=16, choices=range(1, 33))
    parser.add_argument("-n", "--no_numbers", action='store_true', help="Do not use Numbers")
    parser.add_argument("-p", "--print_pwd", action='store_true', help="Prints password to STDOUT")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-s", "--no_special_chars", action='store_true', help="Do not use Special Characters")
    group.add_argument("-cs", "--custom_special_chars", metavar='', nargs='+', default=list(string.punctuation),
                       help="Input Space Separated Special Characters")
    args = parser.parse_args()

    generate_password(pwd_length=args.pwd_length,
                      no_numbers=args.no_numbers,
                      no_special_chars=args.no_special_chars,
                      custom_special_chars=args.custom_special_chars,
                      print_pwd=args.print_pwd)


if __name__ == "__main__":
    main()
