/* fwsyslog-convert.cpp
 * Produces a csv output using Juniper NSM firewall syslog-ng logs
 * 
 * Tested on:
 * Product Name: NetScreen-2000
 * Serial Number: 0079052007000102, Control Number: 00000000
 * Hardware Version: 3010(0)-(04), FPGA checksum: 00000000, VLAN1 IP (0.0.0.0)
 * Software Version: 5.4.0ev8.0, Type: Firewall+VPN
 * OS Loader Version: 1.1.5
 *
 * By:
 * Jeremy Villegas
 * Network Analyst, IITS
 * California State University, San Marcos
 * Office: 760-750-4798 | Mobile: 858-412-0108
 * 
 * 07/02/2008  JV - Fixed bug which caused the logging to fall short when
 *                  the device did a logging statistics update
 * 08/14/2008  JV - Combined screen dump and csv output into one program
 *                  and integrated command line switches
 * 09/22/2008  JV - Converted parts of the program to C++ to accomodate
 *                  the inet libraries for hostname resolution.
 * 10/01/2008  JV - Completed hostname resolution option
 * 10/22/2008  JV - Fixed a bug that would cause memory swapping issues
 *                  when the linked list got too large. Also added the ability
 *                  to resolve source hostnames as well as destination.
 * 11/06/2008  JV - Limited the amount of cached hostnames to 15 and added
 *                  customizable setting.
 * 02/24/2009  JV - Change format of the output fields to reference the 
 *                  policy ID  
 *
 * 
 */

#include<iostream>
#include<string>
#include<fstream>
#include<stdlib.h>
#include<stdio.h>
#include<getopt.h>
#include<string.h>
#include<iomanip>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<netdb.h>

// const
const int MAXIMUM_CACHED_HOSTNAMES = 15;
const int RELEASE_VERSION = 42;
const int REMOVE_FIELD_TAGS = 1;
const int FIELD_LENGTH = 32;
using namespace std;

// protos
string stringReplace(string,string,string);
int stringFind(string inString, string searchString);
string getField(string,string); /* by searching */
string getField(string,int); /* by field number */
void empty_list();
int console_output_flag=0,res_src_flag=0,res_dst_flag=0,table_header_flag=1;
char *nslookup(char*);
struct ip_table *ipt_top=NULL;
int list_size=0;

// struct for hostname resolution
struct ip_table{
  struct ip_table *next;
  char *ip_address;
  char *hostname; 
};


int main(int argc,char *argv[]) {
  char in[2048],*name,buf[254],b[254];
  char *delim,*infile,*outfile,*n;
  string ins,cstr,sout;
  int i=0,c,argerr=0;
  ifstream fin;
  ofstream fout;

  // deal with cmd line switches
  while((c=getopt(argc,argv,"odhs"))!=-1) {
    switch(c) {
      case 'o':
        console_output_flag++;
        break;
      case 'h':
        /* supress header for tables */
        table_header_flag--;
        break;
      case 'd':
        /* resolve destination hostnames */
        res_dst_flag++;
        break;
      case 's':
        /* resolve source hostnames */
        res_src_flag++;
        break;
      case '?':
        /* Not found */
        argerr++;
        break;
    }
  }
 
  // help
  infile=argv[optind++];
  outfile=argv[optind++];
  if((infile==outfile)||(infile==NULL))argerr++;
  if(argerr){
    cout<<"Usage: "<<argv[0]<<" [OPTION] <input-file> [output-file]\n";
    cout<<"Juniper firewall log parser.  Takes a raw firewall log and converts it to a\n";
    cout<<"readable format.\n\n";
    cout<<"    -d       Automatically resolve destination hostnames\n";
    cout<<"    -h       Surpress header line when showing tables\n";
    cout<<"    -o       Output data to the console instead of to the file\n";
    cout<<"    -s       Automatically resolve source hostnames\n\n";
    cout<<"Report bugs to <jvillegas@csusm.edu>. [v0." << RELEASE_VERSION <<"]\n";
    exit(EXIT_FAILURE);
  }
  n=(char*)malloc(sizeof(char)*strlen(infile));
  if(n==NULL) perror("out of memory!");
  strcpy(n,infile);
  if(outfile==NULL){
    outfile=(char*)malloc(sizeof(char)*strlen(n)+4);
    if(outfile==NULL) perror("out of memory!");
    strcpy(outfile,strcat(n,".csv"));
  }
  fin.open(infile);
  fout.open(outfile);
  if(!fin) {
    cout<<"Error opening " << infile << "\n";
    exit(EXIT_FAILURE);
  }
  if(console_output_flag){
    if(table_header_flag){
      cout << "Month,Day,Time,Policy,Service,Source Zone,Destination Zone,Action,Source Address,Source Port,Destination,Destination Port";
      // old pretty print for 
      /*cout << "DATE/TIME       POLICY SERVICE                          SRCZONE  DSTZONE  ACTION";
      cout << "  SOURCE ADDRESS                   PORT   DESTINATION ADDRESS              PORT";*/
      cout << endl;
    }
    delim=",";
  } else {
    if(table_header_flag)
      sout = "Month,Day,Time,Policy,Service,Source Zone,Destination Zone,Action,Source Address,Source Port,Destination,Destination Port";
    if(console_output_flag)
      cout<<sout<<endl;
    else
      fout<<sout<<endl;
    delim=","; 
  }
 
  /* load contents of file into a buffer */
  while (1){
    fin.getline(in,2048);
    /* We done? */
    if (!in[0]) exit(0);
    /* Replaces spaces with commas and trim double spaces */
    ins = stringReplace(in,"  "," ");
    ins = stringReplace(ins," ",",");
	
    /* Replace Endpoint Mapper string */
    ins = stringReplace(ins,",Endpoint,Mapper"," Endpoint Mapper");
	    
    /* Replace extra spaces in ntp protocol field */
    ins = stringReplace(ins,"Network,Time","Network Time");

    /* Replace zone screwers */
    ins = stringReplace(ins,",src,zone",",src_zone");
    ins = stringReplace(ins,",dst,zone",",dst_zone");

    /* Get Date */
    sout=getField(ins,0);
    sout+= delim + getField(ins,1);

    /* Get Time */
    sout+= delim + getField(ins,2);
		
    /* Get Policy_ID */
    sout+= delim +  getField(ins,"policy_id");

    /* Get service */
    sout+= delim + getField(ins,"service");

    /* Get Source_Zone */	
    sout += delim + getField(ins,"src_zone");
    
    /* Get Dest_Zone */
    sout += delim + getField(ins,"dst_zone");

    /* Get FW-Action */
    sout += delim + getField(ins,"action");

    /* Get source address */
    cstr=getField(ins,"src=");
    if(res_src_flag){
      for(i=0;i<50;i++)
        buf[i]=cstr[i];
      strcpy(b,buf);
      name=nslookup(b);
      if(name==NULL)name=buf;
      sout += delim;
      sout += res_src_flag?name:cstr;
      name=NULL;
    } else
      sout += delim + cstr;
  
    /* Get source port */
    sout += delim + getField(ins,"src_port");

    /* Get destination address */
    cstr=getField(ins,"dst=");
    if(res_dst_flag){
      for(i=0;i<50;i++)
        buf[i]=cstr[i];
      strcpy(b,buf);
      name=nslookup(b);
      if(name==NULL)name=buf;
      sout += delim;
      sout += res_dst_flag?name:cstr;
      name=NULL;
    } else
      sout += delim + cstr; 

    /* Get destination port */
    sout += delim + getField(ins,"dst_port");

    /* All done */
    if(!stringFind(ins,",Log,statistics;")){
      if(console_output_flag){
        /* print the output to the screen */
        while(stringFind(sout,",")!=0){
          break; 
        }
        cout<<sout<<endl; 
      } else {
        /* print to output file */
        fout<<sout<<endl;
      }
    }
  }
  fin.close();
  fout.close();
  return(0);
}
 
string stringReplace(string inString, string searchString,string replaceString) {
  int pos = 0;
  while((pos=inString.find(searchString,pos))!=(int)string::npos) {
    inString.replace(pos,searchString.size(),replaceString);
    pos++;
  }
  return inString;
}

int stringFind(string inString, string searchString) {
  return inString.find(searchString)!=string::npos?inString.find(searchString):0;
}
	
string getField(string inString, string field) {
  string::size_type startPos=inString.find(field);
  if (startPos!=string::npos) {
    string fnd;
    fnd.assign(inString,startPos,inString.size());
    string::size_type  endPos=fnd.find(",");
    if (REMOVE_FIELD_TAGS>0) {
      inString = inString.substr(startPos,endPos);
      return inString.substr(inString.find("=")+1,inString.size());
    }
    return inString.substr(startPos,endPos);
  }
  return "";
}

string getField(string inString, int fieldNumber) {
  string f;
  f=inString;
  for (int x=fieldNumber;x>0;x--)
    f=f.substr(f.find(",")+1,f.size());
  return f.substr(0,f.find(","));
}

char *nslookup(char *a) {
  struct hostent *gethostbyaddr(const char *addr, int len, int type);
  struct in_addr addr;
  struct hostent *he=NULL;
  struct ip_table *ipt_node=ipt_top,*ipt_new,*ipt_next;
  int x=0;

  /* did we pass anythign in? */
  if(a==NULL)return(NULL);

  /* See if its in the list before doing anything */
  while(ipt_node!=NULL){
    if(strcmp(ipt_node->ip_address,a)==0)
      return(ipt_node->hostname);
    ipt_node=ipt_node->next;
  }

  /* Prepare ipt_new to make a new one */
  ipt_new=(struct ip_table*)malloc(sizeof(ip_table));
  if(ipt_new==NULL)perror("out of memory");
  ipt_new->ip_address=(char*)malloc(sizeof(char)*strlen(a)+1);
  if(ipt_new->ip_address==NULL)perror("out of memory");
  strcpy(ipt_new->ip_address,a);
  strcat(ipt_new->ip_address,"\0");

  /* Find out the hostname from dns */
  inet_aton(a,&addr);
  he=gethostbyaddr(&addr, sizeof(in_addr), AF_INET);
  if(he!=NULL){
    ipt_new->hostname=(char*)malloc(sizeof(char)*strlen(he->h_name)+1);
    if(ipt_new->hostname==NULL)perror("out of memory");
    strcpy(ipt_new->hostname,he->h_name);
    strcat(ipt_new->hostname,"\0");
  } else {
    ipt_new->hostname=(char*)malloc(sizeof(char)*strlen(a)+1);
    if(ipt_new->hostname==NULL)perror("out of memory");
    strcpy(ipt_new->hostname,a);
    strcat(ipt_new->hostname,"\0");
  }
  /* Load it up into the linked list */
  if(ipt_top==NULL)ipt_new->next=NULL;
  else ipt_new->next=ipt_top;
  ipt_top=ipt_new; 
  if(list_size++>MAXIMUM_CACHED_HOSTNAMES){
    ipt_node=ipt_top;
    while(ipt_node!=NULL){
      if(x>list_size&&x++>MAXIMUM_CACHED_HOSTNAMES){
        ipt_next=ipt_node->next; 
        delete(ipt_node->ip_address);
        delete(ipt_node->hostname);
        delete(ipt_node);
        ipt_node=ipt_next;
      } else ipt_node=ipt_node->next;
    } 
  }
  /* Return your hostname */
  return(ipt_new->hostname);
}


