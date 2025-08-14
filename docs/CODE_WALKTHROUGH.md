<h1 align="center"> Code Walkthrough </h1>

This document provides a detailed explanation of the program’s internal workflow. It describes how each part of the code operates,
the sequence of execution, and the conditions under which each step and class is triggered.

<br>


# Classes
These images show the flowchart of the code.
The first image, with the circles, displays the classes and their corresponding colors, making it easier to identify where each process
takes place.

<p align="center">
  <img src="https://github.com/olivercalazans/netxplorer/blob/main/images/classes.drawio.svg" alt="Classes" width="70%"/>
</p>

<br>

# Flowchart
The second image shows which processes are being executed and where. If an error occurs during any of the processes, the execution will
stop, and an error message will be displayed, indicating where the error occurred.

>[!NOTE]
>The Data class (blue circle) is an instance that holds the shared data modified by the processing instances.

<p align="center">
  <img src="https://github.com/olivercalazans/netxplorer/blob/main/images/netxplorer.drawio.svg" alt="Flowchart" width="60%"/>
</p>
