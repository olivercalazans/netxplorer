<h1 align="center"> NetXplorer </h1>

NetXplorer is a Python-based command-line tool for gathering information about networks and devices. Inspired by Nmap, it offers similar
functionality while focusing on simplicity and ease of use. Developed on Linux, it leverages Linux-specific libraries, which currently
limit its compatibility with Windows. However, it runs seamlessly on WSL (Windows Subsystem for Linux). NetXplorer requires no external
Python library.

<br>

# Principal Functionalities
 - Port scanning
 - Banner Grabbing
 - Network mapping

<br>

# Requirements and Compatibility
 - **Environment**: 
     Linux distributions (This tool is compatible with WSL and can be used within it).

 - **Dependency**: Python 3.10 or higher.



<br>



# How to install
To simplify the installation, a file named [setup.sh](https://github.com/olivercalazans/netxplorer/blob/main/src/netxplorer/setup.sh) has been created. Just run it, and everything will be set up for you to use the code.

<br>

# Running manually 
If you'd prefer to use the code manually, follow the steps below.


<br>

  - **Download files**: You can download the files directly from this repository or use git clone:
    ```bash
    git clone https://github.com/olivercalazans/netxplorer.git
    ```
<br>

  - **1st - Python Installation**: Ensure that you have Python 3.10 or higher installed on your machine. You can download it from [python.org](https://www.python.org/downloads/) or use the command below.
    ``` bash
    sudo apt install -y python3.11
    ```

<br>

 - **2nd - Run the code**:
    ``` bash
    sudo python3 main.py <command> <arguments>
    ```
