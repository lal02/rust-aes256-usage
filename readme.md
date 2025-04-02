# AES256

 

Dieses kleine Rust CLI Programm nutzt die AES-GCM Crate um eine symmetrische Verschlüsselung von Texten zu implementieren.

Dabei gibt es folgende Optionen:

- Einlesen und verschlüsseln von Dateien mit random key und nonce

- Einlesen und entschlüsseln von Dateien mit key und nonce in übergebenem file

- Einlesen und verschlüsseln von Texten über cli-args mit random key und nonce

- Einlesen und entschlüsseln von Texten über cli-args mit key und nonce in übergebenem file

- Ausgabe in Konsole, aktuellem File (overwrite), neues File

- Bei Verschlüsselung generieren eines Files mit verwendetem Key und Nonce zur Wiederverwendung bei der Entschlüsselung

 

# Args

- f [path] = filepath for file to be encrypted/decrypted

- i [text] = input to be encrypted/decrypted

- t [path] = target path for result file

- k [path] = filepath to file with key and nonce

- e = encryption boolean flag

- d = decryption boolean flag

- o = overwrite file boolean flag

- c = console output boolean flag

 

Hinweis:

- Es kann nicht gleichzeitig verschlüsselt und entschlüsselt werden.

- Beim entschlüsseln wird muss immer -k mit path zu file mit korrektem key und nonce verwendet werden, ansonsten kann nicht korrekt entschlüsselt werden.

- -o kann nur in Kombination mit einem input file genutzt werden

- Es kann entweder ein input file oder ein input Text genutzt werden, nicht beides gleichzeitig

# Herausforderungen bei diesem Projekt:
- Umgang mit Bytes und Hexadezimal-"Strings"
- Umgang mit Files und CLI Args
- Einlesen und arbeiten mit in aes-256 crate 
- Umwandlung von String-Eingabe zu Bytes und Hexadezimal im Zuge von Verschlüsselung