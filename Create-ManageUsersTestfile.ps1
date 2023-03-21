#Creates a test xml file to test your manage users script
#filename is the name of the file to save
#ID is any suffix that will make the users and groups uniuqe 
#    use a different ID each time to create unique test files
param ($Filename="", $ID=$null)

function Get-MD5([string]$inputstring=''){
    if ($inputstring -eq ''){$inputstring=[datetime]::Now}
    $cryptoServiceProvider = [System.Security.Cryptography.MD5CryptoServiceProvider];
    $hashAlgorithm = new-object $cryptoServiceProvider
    [char[]]$c=$inputstring
    $hashByteArray = $hashAlgorithm.ComputeHash($c);
    foreach ($byte in $hashByteArray) { $result += “{0:X2}” -f $byte}
    $result.Substring(0,6)
}

Function Create-UsersXML($ID){
    $xmlString=@"
<root>
	<user>
		<account>Chico$ID</account>
		<firstname>Leonard</firstname>
		<lastname>Marx</lastname>
		<description>Pianist</description>
		<password>Password1</password>
		<manager></manager>
		<ou>comedians$ID</ou>
		<memberOf>
			<group>Marx Brothers$ID</group>
			<group>GGMusicians$ID</group>
		</memberOf>
	</user>
	<user>
		<account>Harpo$ID</account>
		<firstname>Arthur</firstname>
		<lastname>Marx</lastname>
		<description>Original firstname was Adolph</description>
		<password>Password2</password>
		<manager>Chico$ID</manager>
		<ou>comedians$ID</ou>
		<memberOf>
			<group>Marx Brothers$ID</group>
			<group>Domain Admins</group>
		</memberOf>
	</user>
	<user>
		<account>Groucho$ID</account>
		<firstname>Julius Heney</firstname>
		<lastname>Marx</lastname>
		<description>Played guitar and sang</description>
		<password>Password3</password>
		<manager>Chico$ID</manager>
		<ou>comedians$ID</ou>
		<memberOf>
			<group>Marx Brothers$ID</group>
			<group>GGMusicians$ID</group>
		</memberOf>

	</user>
	<user>
		<account>Gummo$ID</account>
		<firstname>Milton</firstname>
		<lastname>Marx</lastname>
		<description>Left the troop to serve in WWII</description>
		<password>Password4</password>
		<manager>Chico$ID</manager>
		<ou>comedians$ID</ou>
		<memberOf>
			<group>Marx Brothers$ID</group>
		</memberOf>

	</user>
	<user>
		<account>Zeppo$ID</account>
		<firstname>Herbert</firstname>
		<lastname>Marx</lastname>
		<description>Vocalist</description>
		<password>Password5</password>
		<manager>Chico$ID</manager>
		<ou>comedians$ID</ou>
		<memberOf>
			<group>Marx Brothers$ID</group>
		</memberOf>

	</user>
	<user>
		<account>Manfred$ID</account>
		<firstname>Manfred</firstname>
		<lastname>Marx</lastname>
		<description>Died as an infant</description>
		<password>Password6</password>
		<manager>Chico$ID</manager>
		<ou>comedians$ID</ou>
		<memberOf>
			<group>Marx Brothers$ID</group>
		</memberOf>
	</user>
</root>

"@
$xmlstring
}
if ($Filename -eq ''){
    write-host -ForegroundColor red "usage: Create-ManageUsersTestfile.ps1 -Filname <outputfile> [-ID <SomeID>]"
    write-host -ForegroundColor red "Where: <outputfile> is the filename you want to create"
    Write-Host -ForegroundColor red "       <SomeID> is a suffix that will make the sample data unique"
    Write-Host -ForegroundColor red "           use an different ID each time to create unique files"
    Write-Host -ForegroundColor red "           if ID is ommited a random suffix will be generated"
}else{
    if($id -eq $null){$id=get-md5}
    Create-UsersXML -ID $ID|Out-File -FilePath $Filename
    write-host "File $Filename created"
}