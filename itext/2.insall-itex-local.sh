#!/bin/bash


mvn install:install-file \
  -Dfile=target/itext-2.1.7.jar \
  -DgroupId=com.lowagie \
  -DartifactId=itext \
  -Dversion=2.1.7 \
  -Dpackaging=jar