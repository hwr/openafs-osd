/*
 Copyright Christof Hanke (christof.hanke@rzg.mpg.de)
 parts: copyright IBM 
*/

#include <afsconfig.h>
#include <afs/param.h>
#include "cmd.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <time.h>

void PrintDate(afs_uint32 intdate)
{
    time_t date;
    char month[4];
    char weekday[4];
    int  hour, minute, second, day, year;
    char *timestring;
    char *months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug",
                         "Sep", "Oct", "Nov", "Dec"};
    int i;

    if (!intdate) printf(" never       "); else {
        date = intdate;
        timestring = ctime(&date);
        sscanf(timestring, "%s %s %d %d:%d:%d %d",
                (char *)&weekday,
                (char *)&month, &day, &hour, &minute, &second, &year);
        for (i=0; i<12; i++) {
           if (!strcmp(month, months[i]))
                break;
        }
        printf(" %04d-%02d-%02d", year, i+1, day);
    }
}

void PrintTime(afs_uint32 intdate)
{
    time_t date;
    char month[4];
    char weekday[4];
    int  hour, minute, second, day, year;
    char *timestring;
    char *months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug",
                         "Sep", "Oct", "Nov", "Dec"};
    int i;

    if (!intdate) printf(" never       "); else {
        date = intdate;
        timestring = ctime(&date);
        sscanf(timestring, "%s %s %d %d:%d:%d %d",
                (char *)&weekday,
                (char *)&month, &day, &hour, &minute, &second, &year);
        for (i=0; i<12; i++) {
           if (!strcmp(month, months[i]))
                break;
        }
        printf(" %04d-%02d-%02d %02d:%02d:%02d", year, i+1, day, hour, minute, second);
    }
    return;
}

void sprintDate( char *string, afs_uint32 intdate)
{
    time_t date;
    char month[4];
    char weekday[4];
    int  hour, minute, second, day, year;
    char *timestring;
    char *months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug",
                         "Sep", "Oct", "Nov", "Dec"};
    int i;
    if (!intdate) 
        printf("never"); 
    else {
        date = intdate;
        timestring=ctime(&date);
        sscanf(timestring, "%s %s %d %d:%d:%d %d",
                (char *)&weekday,
                (char *)&month, &day, &hour, &minute, &second, &year);
        for (i=0; i<12; i++) {
           if (!strcmp(month, months[i]))
                break;
        }
        sprintf(string,"%04d-%02d-%02d", year, i+1, day);
    }
    return;
}

/*

Basic Table operations

*/

struct TableCell* setTableCell(struct TableCell *aCell, char *Content, int Width,int Justification) {
    aCell->Width=Width;
    /* truncate Cell->Content at aCell->Width */
    strncpy(aCell->Content,Content,min(T_MAX_CELLCONTENT_LEN,aCell->Width)); 
    aCell->Content[aCell->Width]='\0';
    aCell->Justification=Justification;
    return aCell;
}

void printTableBody(struct Table *Table) {
    struct TableRow *aRow;
    aRow=Table->Body;
    if (!aRow) return;
    Table->printRow(Table,aRow->Head);
    aRow=aRow->next;
    while (aRow != NULL) {
	Table->printRow(Table,aRow->Head);
        aRow=aRow->next;
    }
}

int * newTableLayout(int CellsperRow) {
    int *CellWidth=NULL;
    if ( (CellWidth=malloc(CellsperRow*sizeof(int))) == NULL) {
          fprintf(stderr,"Internal Error. Cannot allocate memory for table printout\n");
          exit(EXIT_FAILURE);
    }
   return CellWidth;
}


struct TableCell* appendTableCell(struct TableCell *aCell, char *Content, int Width,int Justification) {
    /* go to end of list*/
    while (aCell->next != NULL) {
        aCell=aCell->next;
    }
    if ( (aCell->next=malloc(sizeof(struct TableCell))) == NULL) {
          fprintf(stderr,"Internal Error. Cannot allocate memory for table printout\n");
          exit(EXIT_FAILURE);
    }
    aCell=aCell->next;
    aCell->Width=Width;
    /* truncate Cell->Content at Cell->Width */
    strncpy(aCell->Content,Content,min(T_MAX_CELLCONTENT_LEN,aCell->Width)); 
    aCell->Content[aCell->Width]='\0';
    aCell->Justification=Justification;
    aCell->next=NULL;
    return aCell;
}

struct TableRow* setBodyRow(struct TableRow *aRow, struct TableCell *Head) {
    aRow->Head=Head; 
    return aRow;
}

struct TableRow* appendBodyRow(struct TableRow *aRow, struct TableCell *Head) {
    while (aRow->next != NULL) {
        aRow=aRow->next;
    }
    if ( (aRow->next=malloc(sizeof(struct TableRow))) == NULL) {
          fprintf(stderr,"Internal Error. Cannot allocate memory for table printout\n");
          exit(EXIT_FAILURE);
    }
    aRow=aRow->next;
    aRow->next=NULL;
    aRow->Head=Head; 
    return aRow;
}


void printTable(struct Table *Table) { 
  
    if (!Table->printHeader || ! Table->printBody || !Table->printFooter) {
	fprintf(stderr,"Cannot print uninitialized table.\n");
	exit(EXIT_FAILURE);
    }
    Table->printHeader(Table);
    Table->printBody(Table);
    Table->printFooter(Table);
}


/* ASCII - functions */

void printTableRow_ASCII(struct Table *Table,struct TableCell *aCell) {
        int rpad = 0;
        int lpad = 0;
   
    if (!aCell)
	return;
    
    if (Table->Type == T_TYPE_ASCII_FULLNET) 
	printf("%c",Table->CellSeparator);
    if (aCell->Justification == T_CELL_JUST_RIGHT ) {
        printf("%-*s",aCell->Width,aCell->Content);
    } else if (aCell->Justification == T_CELL_JUST_LEFT ) {
        printf("%*s",aCell->Width,aCell->Content); 
    } else if (aCell->Justification == T_CELL_JUST_CENTRE ) {
        rpad=(aCell->Width-strlen(aCell->Content))/2;
	lpad=aCell->Width-strlen(aCell->Content)-rpad;
	if (lpad)
	    printf("%*s",lpad," ");
        printf("%s",aCell->Content);
        if (rpad)
            printf("%*s",rpad," ");	
    }
    printf("%c",Table->CellSeparator);

    aCell=aCell->next;
    while (aCell != NULL) {
        if (aCell->Justification == T_CELL_JUST_RIGHT ) {
            printf("%-*s",aCell->Width,aCell->Content);
        } else if (aCell->Justification == T_CELL_JUST_LEFT ) {
            printf("%*s",aCell->Width,aCell->Content);
        } else if (aCell->Justification == T_CELL_JUST_CENTRE ) {
            rpad=(aCell->Width-strlen(aCell->Content))/2;
            lpad=aCell->Width-strlen(aCell->Content)-rpad;
            if (lpad)
                printf("%*s",lpad," ");
            printf("%s",aCell->Content);
            if (rpad)
                printf("%*s",rpad," ");
        }
        if (aCell->next)
            printf("%c",Table->CellSeparator);
        aCell=aCell->next;
    }
    if (Table->Type ==  T_TYPE_ASCII_FULLNET )
	printf("%c",Table->CellSeparator);
    printf("\n");
    return;
}

void printTableHeader_ASCII(struct Table *Table) {

    int i;
    if (Table->Type == T_TYPE_ASCII_FULLNET) {
        printf("%c",Table->CellSeparator);
        for(i=0;i<Table->RowLength;i++)
            printf("%c",Table->RowSeparator);
        printf("%c\n",Table->CellSeparator);
    }

    printTableRow_ASCII(Table,Table->Header);

    if (Table->Type == T_TYPE_ASCII_FULLNET) {
        printf("%c",Table->CellSeparator);
    }
    if (Table->Type == T_TYPE_ASCII_FULLNET || Table->Type == T_TYPE_ASCII_INNERLINE) {
        for(i=0;i<Table->RowLength;i++)
            printf("%c",Table->RowSeparator);
	if (Table->Type == T_TYPE_ASCII_FULLNET)
            printf("%c",Table->CellSeparator);
	printf("\n");
    }
    return;
}


void printTableFooter_ASCII(struct Table *Table) {
    int i;
    if (Table->Type != T_TYPE_ASCII_FULLNET )
	return;
    printf("%c",Table->CellSeparator);
    for(i=0;i<Table->RowLength;i++)
        printf("%c",Table->RowSeparator);
    printf("%c\n",Table->CellSeparator);
    if (Table->Footer) {
        Table->printRow(Table,Table->Footer);
        printf("%c",Table->CellSeparator);
        for(i=0;i<Table->RowLength;i++)
            printf("%c",Table->RowSeparator);
        printf("%c\n",Table->CellSeparator);
    }
    return;
}

/* HTML - output functions */

void printTableRow_HTML(struct Table *Table,struct TableCell *aCell) {
    if (!aCell)
	return;

    if (aCell == Table->Header) 
	printf("\t\t<tr>\n");
    else 
	printf("\t\t<th>\n");

    if (aCell->Justification == T_CELL_JUST_RIGHT )
	printf("\t\t<td style=\"text-align=right\">"); 
    else if (aCell->Justification == T_CELL_JUST_LEFT )
        printf("\t\t<td style=\"text-align=left\">"); 
    else if (aCell->Justification == T_CELL_JUST_CENTRE )
        printf("\t\t<td style=\"text-align=center\">"); 
    printf("%s",aCell->Content);
    printf("\t\t</td>\n");

    aCell=aCell->next;
    while (aCell != NULL) {
        if (aCell->Justification == T_CELL_JUST_RIGHT )
           printf("\t\t<td style=\"text-align=right\">");
        else if (aCell->Justification == T_CELL_JUST_LEFT )
            printf("\t\t<td style=\"text-align=left\">");
        else if (aCell->Justification == T_CELL_JUST_CENTRE )
            printf("\t\t<td style=\"text-align=center\">");
        printf("%s",aCell->Content);
        printf("\t\t</td>\n");
        aCell=aCell->next;
    }
    if (Table->Type == T_TYPE_HTML) {
       if (aCell == Table->Header) 
	    printf("\t\t</tr>\n");
       else 
	    printf("\t\t</th>\n");
    }
    printf("\n");
    return;
}

void printTableFooter_HTML(struct Table *Table) {
    printf("</tbody>\n");
    if (Table->Footer) {
        printf("<tfooter>\n");
        Table->printRow(Table,Table->Footer);
        printf("</tfooter>\n");
    }
    printf("</table>\n");
}

void printTableHeader_HTML (struct Table *Table) {
    printf("<table>\n");
    printf("<thead>\n");
    printTableRow_HTML(Table,Table->Header);
    printf("</thead>\n");
    printf("<tbody>\n");
    return ;
}


/* CSV - output */

void printTableRow_CSV(struct Table *Table,struct TableCell *aCell) {

    if (!aCell)
	return;
    printf("%s",aCell->Content);
    aCell=aCell->next;
    while (aCell != NULL) {
        printf(",%s", aCell->Content);
        aCell=aCell->next;
    }
    printf("\n");
    return;
}

void printTableHeader_CSV (struct Table *Table) {
    printTableRow_CSV(Table,Table->Header);
    return ;
}

void printTableFooter_CSV (struct Table *Table) {
    printTableRow_CSV(Table,Table->Footer);
    return ;
}



void setTableType(struct Table *Table,int TableType) {
    if ( TableType == T_TYPE_ASCII_SPARTAN) {
        Table->CellSeparator=' ';
        Table->RowSeparator='\0';
    } else {
        Table->CellSeparator='|';
        Table->RowSeparator='-';
    }
    Table->Type=TableType;
    switch (TableType) {
        case T_TYPE_ASCII_FULLNET :
	case T_TYPE_ASCII_INNERLINE:
	case T_TYPE_ASCII_SPARTAN :
    		Table->printHeader=printTableHeader_ASCII;
    		Table->printFooter=printTableFooter_ASCII;
    		Table->printRow=printTableRow_ASCII;
		break;
	case T_TYPE_HTML : 
                Table->printHeader=printTableHeader_HTML;
                Table->printFooter=printTableFooter_HTML;
    		Table->printRow=printTableRow_HTML;
                break;
	case T_TYPE_CSV :
                Table->printHeader=printTableHeader_CSV;
                Table->printFooter=printTableFooter_CSV;
    		Table->printRow=printTableRow_CSV;
                break;
	default :
		fprintf(stderr,"Internal data while seeting up the table type.\n");
		exit(1);
    };
    return;
}


void setTableLayout(struct Table *Table,int CellsperRow,int *allCellWidth, int *chosenIdx  ) {
    /* 
       allCellWidth is an array holding the cellwidth of all possible fields.
       chosenIdx is an array holding the indexes of those fields we want to use.
    */
    int i;
    Table->CellsperRow=CellsperRow;
    if ( (Table->CellWidth= malloc(CellsperRow*sizeof(int))) == NULL) {
          fprintf(stderr,"Internal Error. Cannot allocate memory for table printout\n");
          exit(EXIT_FAILURE);
    }
    Table->RowLength = -1;
    for (i=0;i<CellsperRow;i++) {
	Table->CellWidth[i]=allCellWidth[chosenIdx[i]];	
        Table->RowLength += allCellWidth[chosenIdx[i]] + 1; 
    }

    return;
}

/* Constructors */

struct TableCell* newTableCell(void) {
    struct TableCell *aCell=NULL;
    if ( (aCell=malloc(sizeof(struct TableCell))) == NULL) {
          fprintf(stderr,"Internal Error. Cannot allocate memory for new TableCell.\n");
          exit(EXIT_FAILURE);
    }
    aCell->Width=0;
    aCell->Content[0]='\0';
    aCell->Justification=0;
    aCell->next =NULL;
    aCell->append=appendTableCell;
    aCell->set=setTableCell;
    return aCell;
}

struct TableRow* newTableRow(void) {
    struct TableRow *aRow=NULL;
    if ( (aRow=malloc(sizeof(struct TableRow))) == NULL) {
          fprintf(stderr,"Internal Error. Cannot allocate memory for new TableRow.\n");
          exit(EXIT_FAILURE);
    }
    aRow->Head=NULL;
    aRow->next=NULL;
    aRow->append=appendBodyRow;
    aRow->set=setBodyRow;
    return aRow;
}

struct Table* newTable(void) {
    struct Table *aTable=NULL;
    if ( (aTable=malloc(sizeof(struct Table))) == NULL) {
          fprintf(stderr,"Internal Error. Cannot allocate memory for new TableRow.\n");
          exit(EXIT_FAILURE);
    }
    aTable->Type=-1;
    aTable->CellsperRow=-1;
    aTable->CellWidth=NULL;
    aTable->RowLength=-1; 
    aTable->CellSeparator='\0';
    aTable->RowSeparator='\0';
    aTable->Header=NULL;
    aTable->Body=NULL;
    aTable->Footer=NULL;
    aTable->printHeader=NULL;
    aTable->printBody=NULL;
    aTable->printFooter=NULL;
    aTable->printRow=NULL;
    aTable->printBody=printTableBody;
    aTable->setLayout=setTableLayout;
    aTable->setType=setTableType;
    aTable->newTableLayout=newTableLayout;
    return aTable;
}


void freeTableCellList(struct TableCell *Header) {
    struct TableCell *aCell;
    while (Header)  {
        aCell=Header->next;
        free(Header);
        Header=aCell;
    }
}

void freeTableRow( struct TableRow *Header) {
    struct TableRow *aRow;
    while (Header) {
	aRow=Header->next;
	freeTableCellList(Header->Head);
	free(Header);
	Header=aRow;
    }
}

void freeTable(struct Table *aTable) {
    freeTableCellList(aTable->Header);
    freeTableCellList(aTable->Footer);
    freeTableRow(aTable->Body);
    free(aTable);
}
