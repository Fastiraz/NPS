#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h> // idk why

/* gcc -o sniffer sniffer.c -lpcap */

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void print_packet(const u_char *packet, int len);

int main(int argc, char *argv[])
{
    pcap_if_t *alldevs; /* list of all available devices */
    pcap_if_t *d; /* pointer to a device */
    char errbuf[PCAP_ERRBUF_SIZE]; /* error buffer */
    pcap_t *handle; /* packet capture handle */
    FILE *logfile; /* log file */

    /* Get the list of all available devices */
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Couldn't find any devices: %s\n", errbuf);
        return(2);
    }

    /* Use the first device in the list */
    d = alldevs;
    if (d == NULL) {
        fprintf(stderr, "Couldn't find any devices\n");
        return(2);
    }

    /* Open the device for capturing */
    handle = pcap_open_live(d->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", d->name, errbuf);
        return(2);
    }

    /* Open the log file */
    logfile = fopen("file.txt", "w");
    if (logfile == NULL) {
        fprintf(stderr, "Couldn't open log file: %s\n", strerror(errno));
        return(2);
    }

    /* Start capturing packets */
    pcap_loop(handle, -1, got_packet, (u_char *)logfile);

    /* Clean up */
    pcap_close(handle);
    fclose(logfile);
    return(0);
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    FILE *logfile = (FILE *)args; /* log file */

    /* Print the packet */
    printf("\n\nPacket captured with length: %d\n", header->len);

    int i;
    for (i = 0; i < header->len; i++) {
        printf("%02x ", packet[i]);
        if ((i + 1) % 16 == 0) {
            printf("\n");
        }
    }
    printf("\n");
    if (header->len > 0) {
        const u_char *bytes;
        printf("####################################\n");
        print_packet(packet, header->len);
    }

    /* Log the packet to file */
    fprintf(logfile, "\n\nPacket captured with length: %d\n", header->len);
    for (i = 0; i < header->len; i++) {
        fprintf(logfile, "%02x ", packet[i]);
        if ((i + 1) % 16 == 0) {
            fprintf(logfile, "\n");
        }
    }
    fprintf(logfile, "\n");
}

/* That's for "decrypt" hexa */
void print_packet(const u_char *packet, int len) {
  printf("Packet: ");
  for (int i = 0; i < len; i++) {
    if (isprint(packet[i]))
      printf("%c ", packet[i]);
    else
      printf(". ");
  }
  printf("\n");
}
