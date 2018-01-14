# clcl
The com.ltsllc Crypto Library.  A library for making crypto tasks easier in Java

clcl doesn't, for the most part, actually do anything.  It just makes other tools (in particular bouncy castle) easier to use. 

clcl was created for the miranda system, but became a project in it's own right when I recognized it's usefullness.  For some strange 
reason, Java has no way of dealing with PEM files, and has no way of signing a CSR to create a certificate.  This is odd, given how 
ubitiquitous SSL and Java are.  clcl tries to perform these functions in a programmer friendly manner.
