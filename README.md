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

* **Chassis class<br/>**
   
   ```
   # connect testcenter with ip 10.182.32.138 , without reserving any port
   # creating chassis class will auto connect chassis
   chassis = Chassis('10.182.32.138')

   # disconnect chassis
   chassis.disconnect()

   # apply changes ( it will apply automatically)
   chassis.apply()

   # connect testcenter and reserve port
   chassis = Chassis('10.182.32.138', [{ 'location' : '//10.182.32.138/1/1', 'vid': None}, { 'location' : '//10.182.32.138/1/2', 'vid': None}])

   # connect testcenter, reserve port and specify a default vlan with specified vid
   # when you create a device under the port, it will insert a vlan layer with vid 100 for you
   # when you create a streamblock, it will insert a vlan layer with vid 100 for you too
   chassis = Chassis('10.182.32.138', [{ 'location' : '//10.182.32.138/1/1', 'vid': 100}])

   # save xml file
   chassis.save('test_configuration.xml')

   # get chassis serial number
   chassis.serial

   # get chassis ip
   chassis.ip
   ```
