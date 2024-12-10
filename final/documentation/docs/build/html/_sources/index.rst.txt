.. Identifying Services from SYN documentation master file, created by
   sphinx-quickstart on Tue Dec  3 16:11:55 2024.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Identifying Services from SYN documentation
===========================================

The goal of our project is to identify the video streaming service associated 
with a given network flow, based on the first 10 SYN packets. Because streaming 
services generate unique patterns in their network traffic, correctly 
classifying the service from early packets can help improve network traffic 
analysis, QoS optimizations, and privacy considerations.

Related work includes Bronzino et al. The main goal is to reproduce their 
results and demonstrate that even with limited packet data, classification is 
possible.

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   explanation
   notebooks/notebook

