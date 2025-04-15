#!/bin/bash
cd lib
mvn install:install-file \
  -Dfile=bcmail-jdk14-138.jar \
  -DgroupId=bouncycastle \
  -DartifactId=bcmail-bc.jdk \
  -Dversion=1.44 \
  -Dpackaging=jar

mvn install:install-file \
  -Dfile=bcprov-jdk14-138.jar \
  -DgroupId=bouncycastle \
  -DartifactId=bcprov-jdk \
  -Dversion=1.44 \
  -Dpackaging=jar

mvn install:install-file \
  -Dfile=bctsp-jdk14-138.jar \
  -DgroupId=bouncycastle \
  -DartifactId=bctsp-jdk14 \
  -Dversion=1.44 \
  -Dpackaging=jar