# Ms17-010
Determine if a device is vulnerable to EternalBlue - Ms17-010

Run this script on the target machine to know whether it is vulnerable to eternalblue
If the machine is not vulnerable, then it is patched, therefore remove all windows KB update/patch superior to '401..'
```
wusa /uninstall /kb:5003209
```
If the script says that the machine is vulnerable but you still facing this issue, then open group policy editor
`gpedit.msc`
`Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options`
Edit `Network access: Shares that can be accessed anonymously` and add " \ " to the empty list<br><br>
<img src="https://cdn.discordapp.com/attachments/782031360217841664/1194019360193384479/image.png?ex=65aed42f&is=659c5f2f&hm=c3caf2ba6aa5dff3215b85cc8f4fa3a4e7a4b39778281b249ff115b8e08d3925&">
