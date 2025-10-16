from db_access import PostgresDB

class Company:
    def __init__ (self, name):
        self.name = name
        self.id = 0
        self.dba = PostgresDB()
        self.uniqueCriteria = []
        self.authUrl = ""
        self.criteriaString = ""
        self.supportedOperations = []
        self.supportedOperationsStr = ""
        self.authAttributes = []
        self.authAttrStr = ""

    # add a function to load company information in the object
    def loadInfo(self):
        mysql = f"select * from company where upper(name) like upper({self.name})"
        print(mysql)

        # Dont do exact match as LLM might have eliminated articles by mistake
        row = self.dba.fetch_one(
            "select * from company where upper(name) like %s ",
            (f"%{self.name.upper()}%",)
        )

        # row = self.dba.fetch_one( "select * from company where upper(name) like '%upper(%s)%'", (self.name,))

        if row:
            self.id = row.get("id")
            self.name = row.get("name")     # We should not need to do this, but user input could be case incorrect.  And hence use the name in db
            self.authUrl = row.get("auth_url")
            print (row)

            self.uniqueCriteria = self.dba.fetch_all("select * from company_unique_criteria where company_id = %s", (self.id,))
            print (self.uniqueCriteria)

            # iterate through uniqueCriteria and generate a string which an be used for Agent
            for thisCriteria in self.uniqueCriteria:
                if self.criteriaString:
                    self.criteriaString = self.criteriaString + " OR " + thisCriteria['criteria']
                else:
                    self.criteriaString = self.criteriaString + thisCriteria['criteria']

            print (self.criteriaString)

            self.supportedOperations = self.dba.fetch_all("select * from bank_operation where company_id = %s", (self.id,))
            for thisOperation in self.supportedOperations:
                if self.supportedOperationsStr:
                    self.supportedOperationsStr = self.supportedOperationsStr + " , " + thisOperation['name']
                else:
                    self.supportedOperationsStr = self.supportedOperationsStr + thisOperation['name']

            print (self.supportedOperationsStr)

            # Load auth attributes for the company
            self.authAttributes = self.dba.fetch_all("select * from auth_attribute where company_id = %s", (self.id,))
            for thisAttribute in self.authAttributes:
                if self.authAttrStr:
                    self.authAttrStr = self.authAttrStr + " , " + thisAttribute['name']
                else:
                    self.authAttrStr = self.authAttrStr + thisAttribute['name']

            print (self.authAttrStr)
        else:
            return


# self test routine
if __name__ == "__main__":
    myCompany = Company('irst')
    myCompany.loadInfo()
    print (myCompany.name)