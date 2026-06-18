Run:
./start_honeypot.sh

Give permisions if needed:
chmod +x start_honeypot.sh

If you encounter any warnings run: 
./run_if_warnings.sh

Give permisions if needed:
./chmod +x run_if_warnings.sh
----------------------------------------------------------------------
From another terminal window
ssh root@localhost -p 2222
After entering any password you will be derected to the root user folder 
type cd .. then ls to see the fake fs folders 
and try the possible commands from the attacker_showcase.txt file
----------------------------------------------------------------------
Check saved logs in honey/cowrie/var/log/cowrie/ OR from project root folder run:
tail -f cowrie/var/log/cowrie/cowrie.log
/////////////////////////////////////
  cd /home/dan/school/honey/phishing-honeypot && docker compose up-d                                                                                                                                                                                         
  ` 
