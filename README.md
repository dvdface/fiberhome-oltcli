# Changelist
* 1.0.0,  first release

# Feedback

give your feedback by following ways<br/>

* visit https://github.com/dvdface/fiberhome-oltcli (preferred)

* send email to dvdface@gmail.com
  

# How to install

`pip install fiberhome-oltcli`

# Known issues

None <br/>

# Overview

With *fiberhome-oltcli* library, you can easily access olt's commandline interface.<br/>

# How to use
## Use OLTCLI ###
```
   oltcli = OLTCLI.get(OLTModel.AN6000_17, '10.182.33.210', 'GPON', 'GPON')

   oltcli.get_authorization()
```
## Use OLTTelnet ###
```
    telnet = OLTTelnet('10.182.33.210', 'GPON', 'GPON')
    telnet.connect()
    assert telnet.run('config') == ''
    telnet.disconnect()

```
