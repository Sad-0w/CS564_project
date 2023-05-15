#include<Keyboard.h> 
void setup() { 
delay(2000); 
type(KEY_LEFT_CTRL,false); 
type(KEY_LEFT_ALT,false); 
type('t',false); 
Keyboard.releaseAll(); 
delay(1000); 
Keyboard.print("insert command here"); 

delay(10); 
Keyboard.releaseAll(); 
Keyboard.end(); 
} 
void type(int key, boolean release) { 
   Keyboard.press(key); 
   if(release) 
         Keyboard.release(key); 
} 
void print(const __FlashStringHelper *value) { 
   Keyboard.print(value); 
} 
void loop(){} 
