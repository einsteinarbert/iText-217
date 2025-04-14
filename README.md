# Itext fork from v2.1.7 re-upgrade for new Apache 2.0 License 
> Fork from https://github.com/itext/itextpdf/tree/2.1.7

**READ: [Authors](./AUTHORS) for mor details about this fork code.**

## 1. Build & package jar
> Need jdk 8 for build this iText library
- install old dependencies jar into .mvn local
```bash
# from ./itext root folder
cd lib && ./mvn-install.sh
```
- build jar
> mvn clean install package
>> you will see jar file has been built at ./target/itext-2.1.7.jar
- testing with jar file:
```bash
# after copy a test pdf file name `test.pdf` into ./test folder:
cd test && ./build-test.sh
# >> You will see the test will write a text into test.pdf file
```