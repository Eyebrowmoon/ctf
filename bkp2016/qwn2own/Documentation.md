BKP Database API Documentation
==============================

Intro
-----
    The BKP Database JavasScript API allows users to store data that can be kept hidden from other users.
This allows web applications to share one web context between multiple users but yet still be able to store
sensitive information pertaining to each user and keep it secret from the others.

API
---

BKPDataBase.create(dbname, password)
   This function is used to create a database with the name *dbname* protected by the *password*.
   It returns a *DBInstance* which can be used to perform database operations.

BKPDataBase.deldb(dbname, password)
   This can be used to delete a previously created database. Returns the number of deleted databases.

BKPDataBase.getdb(dbname, password)
   In order to retrieve a previously created database, this function can be used.

DBInstance.createStore(stname, type, data, storepin)
   Once a database is created, this function can be used to create a BKPStore with the name *stname*. Here the data
   is stored in some lists and can only be accessed by index. The parameter *type* defines what kind of data will be stored in the BKPStore:
   0 - Integers and/or Strings
   1 - Integers only
   2 - Strings only
   The parameter *data* is the actual data to be stored; a list of values to be stored. *storepin* is the value to be used to access the Store.

DBInstance.createKeyedStore(stname, data, storepin)
   This function is used to create a BKPKeyedStore. It is similar to the BKPStore but here the data is stored as a set of
   key:value pairs. *data* is a dictionary-type that associates keys to values.

BKPStore.getall()
   Returns a list with all the elements in the Store.

BKPStore.insert(idx, data)
   This can be used to insert data into the Store at the given index *idx*. Returns 1 on success and 0 on failure.

BKPStore.get(idx)
   Return the element at index *idx*.

BKPStore.remove(idx)
   Deletes the element at index *idx*.

BKPStore.append(e)
   Appends *e* to the current list of elements in the Store.

BKPStore.cut(sidx, eidx)
   Removes the elements in the range [sidx, eidx].

BKPStore.size()
   Returns the size of the Store in number of elements.

BKPKeyedStore.getall()
   Returns a dictionary with all the elements in the Keyed Store.

BKPKeyedStore.insert(data)
   This can be used to insert data into the Keyed Store. *data* is a dictionary
   that contains the key and value to be inserted.

BKPKeyedStore.get(key)
   Return the value associated with *key*.

BKPKeyedStore.remove(key)
   Deletes the element associated with *key*.

BKPKeyedStore.size()
   Returns the size of the Keyed Store in number of elements.

Examples
--------

Please refer to example.html for some sample usage.
