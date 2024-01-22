# Find-PasswordExposure

Powershell.  Searches the Recorded Future Identity module API to find passwords that have been exposed

Hashes cleartext passwords that are provided, before sending them to the API
        
---

**Parameters**

_Hash_

A SHA256 hash of the password that you are looking up

_Password_

The cleartext value of the password that you are searching for.  This is hashed before being sent to the API

---

**Examples**
        
```powershell
Find-Password -Hash 5649332AC4766C482F458AE0E276D7A5330A1F76816732E7A8C0BE9CCDFA2D1A
```

```powershell
Find-Password -Password littlejerry
```
