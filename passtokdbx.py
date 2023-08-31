import os
import sys
import time
import getpass
import secrets
import datetime

import gpg # pyggpme (python-ggpme)
from pykeepass import create_database



def list_keys(context=None):
    """ List available keys and their capabilities. """
    c = gpg.Context() if context is None else context
    for key in c.keylist():
        user = key.uids[0]
        print(f"\nKeys for {user.name} ({user.email})")
        for subkey in key.subkeys:
            features = []
            if subkey.can_authenticate:
                features.append("auth")
            if subkey.can_certify:
                features.append("cert")
            if subkey.can_encrypt:
                features.append("encrypt")
            if subkey.can_sign:
                features.append("sign")
            print("-> %s %s" %(subkey.fpr, ",".join(features)))



def search_for_key(id, context=None):
    """ Searches available keys for given 'id' and returns first result. """
    if context is None:
        context = gpg.Context()
    for key in context.keylist(id):
        return key
    return None



def decrypt(file, context=None):
    """
    Attempts to decrypt the given file with GPG and returns its plaintext if
    successfull or None.
    """
    c = gpg.Context() if context is None else context
    with open(file, "rb") as f:
        try:
            plaintext, decrypt_result, verify_result = c.decrypt(f)
            plaintext = plaintext.decode()
        except gpg.errors.GPGMEError as e:
            plaintext = None
            print("GPG decrypt() error:", e)
    return plaintext



def extract_entry_data(entry_data):
    """ Returns a tuple of strings (username, password, url, notes) from entry_data """
    password, entry = entry_data.split("\n")[0], entry_data.split("\n")[1:]
    username, url, notes = None, None, []

    for line in entry:
        fields = line.split(":")

        # try to assign the line as username or url on first match
        if username is None and fields[0].lower().strip().startswith("user"):
            username = fields[1].strip()
            continue
        if username is None and fields[0].lower().strip().endswith("mail"):
            username = fields[1].strip()
            continue
        if url is None and fields[0].lower().strip().startswith("url"):
            url = ":".join(fields[1:]).strip()
            continue

        # if nothing matches above, append line to notes
        notes.append(line)

    # convert everything into a string and return
    notes = "\n".join(notes).strip()
    if username is None: 
        username = ""
    if url is None:
        url = ""
    return (username, password, url, notes)



def create_entries(path, db, group):
    """
    DFS visit all gpg files in password-store 'path' and create new
    keepassxc entries for target 'group' in keepassxc database 'db'.
    """
    for file in os.listdir(path):
        if os.path.isdir(path + os.sep + file) and not file.endswith(".git"):
            # create new group and continue from there
            group_name = os.path.basename(file)
            g = db.add_group(group, group_name)
            create_entries(path + os.sep + file, db, g)

        if file.endswith(".gpg"):
            # get and decrypt data for new entry
            entry_name = os.path.basename(file)[:-4]
            entry_data = decrypt(path + os.sep + file)

            if entry_data is None:
                print(f"skipping empty entry '{entry_name}' ({path + os.sep + file}), possible error while decrypting")
                continue

            # create new entry in current group
            username, password, url, notes = extract_entry_data(entry_data)
            db.add_entry(group, entry_name, username, password, url, notes)

            # do not keep sensible data in memory longer than necessary
            password, entry_data = None, None



def get_password_store():
    """ returns absolute path to the password-store directory """
    # use password-store directory given in cmdline if available
    if len(sys.argv) > 1:
        pwstore = os.path.abspath(sys.argv[1])
        if os.path.isdir(pwstore):
            return pwstore

    # get password-store directory from environment variable or use default
    pwstore = os.environ.get("PASSWORD_STORE_DIR")
    if pwstore is None:
        try:
            pwstore = os.environ["HOME"] + os.sep + ".password-store"
        except KeyError as e:
            print(e)
            exit(1)
    return os.path.abspath(pwstore)



def get_gpg_fingerprints():
    """ returns list of GPG identities for which the password-store is initialized """
    # get gpg IDs from environment variable or use default in .gpg-id
    try:
        pwkeys = os.environ["PASSWORD_STORE_KEY"].split(" ")
    except KeyError:
        pwstore = get_password_store()
        gpgid = open(pwstore + os.sep + ".gpg-id").readlines()[0].strip()
        gpgkey = search_for_key(gpgid)
        if gpgkey is None:
            print("Unable to find GPG ID.")
            exit(1)
        pwkeys = [gpgkey.subkeys[0].fpr]
    return pwkeys



def get_database_password():
    """
    Ask user for a password to encrypt the new KeePassXC database with or
    generate a secure one if the password entry is not possible. Return the
    password as a plain text string.
    """
    try:
        password = getpass.getpass(prompt="KeePassXC database password: ")
        if password != getpass.getpass(prompt="Repeat KeePassXC database password to verify: "):
            print("Passwords do not match.")
            exit(0)
    except KeyboardInterrupt:
        exit(0)
    except Exception:
        password = secrets.token_urlsafe(32) # generates 32-byte token
        print("Unable to read password.\nGenerated password:", password)
    return password



def get_database_location():
    """ returns absolute path to the new KeePassXC database """
    # use path given in cmdline if available
    if len(sys.argv) > 2:
        dbpath = os.path.abspath(sys.argv[2])
        if not dbpath.endswith(".kdbx"):
            dbpath += ".kdbx"
        if not os.path.exists(dbpath):
            return dbpath
    
    # store new file in password-store directory
    pwstore = get_password_store()
    current_time = datetime.datetime.now()
    dbpath = os.path.abspath(pwstore + os.sep + f"{os.path.basename(pwstore)}-{current_time.isoformat()}.kdbx") 
    # if path exists already, repeat until datetime is unique
    while os.path.exists(dbpath):
        time.sleep(0.1)
        dbpath = get_database_location()
    return dbpath



def main():
    # retrieve information about password-store
    pwstore = get_password_store()
    print("password-store directory:", pwstore)
    # pwkeys = get_gpg_fingerprints()
    # print("password-store key fingerprints:", pwkeys)

    # get or generate new password for database
    password = get_database_password()
    # location = get_database_location()
    # print("create new KeePassXC database:", location)

    # create new keepass database and forget password
    db, password = create_database("keepass.kdbx", password), None

    # create new groups and entries
    create_entries(pwstore, db, db.root_group)

    # save changes
    db.save()


if __name__ == "__main__":
    main()

