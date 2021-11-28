main:
  gcc -g *.c -o passcheck -lcrypto -Wno-stringop-overflow -lssl
  
