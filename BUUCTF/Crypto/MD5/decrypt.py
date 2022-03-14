import hashlib

def main():
    m = hashlib.md5()
    m.update(b'test')
    print(m.hexdigest())

if __name__ == "__main__":
    main()
    