#!/bin/bash
echo jdk 1.8 compiling
javac -cp ../target/itext-2.1.7.jar TestIText.java
echo running test
java -cp .:../target/itext-2.1.7.jar TestIText

