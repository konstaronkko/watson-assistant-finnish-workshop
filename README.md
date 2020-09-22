**Watson Assistant Finnish Workshop**

**Konsta Rönkkö, Technical Architect, IBM**

**Konsta.ronkko@ibm.com**

**Rakenna suomenkielinen toimistotarvikkeiden myyntibotti Watson Assistantia käyttäen**

Aloita lataamalla tai kloonaamalla tämä repository koneellesi.

Tämä workshop vaatii IBM Cloud-tilin. Voit rekisteröidä ilmaisen kokeiluversion täältä: [https://cloud.ibm.com/registration](https://cloud.ibm.com/registration)

Chatbot rakennetaan käyttäen Watson Assistant-palvelua. Voit luoda oman palvelun kirjautumalla IBM Cloudiin, ja etsimällä Catalog-osiosta Watson Assistant. Valitse Plus Trial-plan ja seuraa ohjeita palvelun luomiseksi.

![](Watson%20Assistant%20Finnish%20Workshop%20v2.0.fld/image000.png)

**Toimistotarvikebotti**

Kun olet luonut Watson Assistant-palvelun, voit aloittaa oman Assistantin rakentamisen painamalla IBM Cloud-tilisi Assistant-palvelusta `Launch Tool`.

![](Watson%20Assistant%20Finnish%20Workshop%20v2.0.fld/image001.png)

  

Tämän jälkeen Assistant-palvelun pitäisi luoda sinulle valmiiksi ensimmäisen Assistanttisi ja Skillisi. Voit jättää kielivalinnaksi English(US): tällä ei ole käyttötarkoituksessamme väliä, hyödynnämme Assistantin ydinkielimallia ilman kielikohtaisia erikoistumisia.

Jos Skilliä ei luotu automaattisesti, voit luoda ensimmäisen Skillisi painamalla aloitussivulta `Create a skill`. Anna skillille nimi; tässä harjoituksessa voit käyttää nimeä `Toimistotarvikebotti`.

![](Watson%20Assistant%20Finnish%20Workshop%20v2.0.fld/image002.png)


Kun Skill on luotu, eteesi avautuu tyhjä näkymä välilehdillä `Intents`, `Entities` ja `Dialog`. Muut välilehdet voit jättää huomiotta; tässä harjoituksessa emme tarvitse muita ominaisuuksia.

Aloitetaan keskustelun suunnittelulla, ja siirrytään luomaan ensimmäiset Intentit.

**Chatbotin keskustelun suunnittelu**

Kun luomme chatbottia, on hyvä keskittyä miettimään oman chatbotin roolia ja tarkoitusta, mitä se palvelee. Näin voimme suunnitella tarvittavan dialogin ja luoda chatbotille oman äänen ja persoonallisuuden, joka sopii sen rooliin. Tämä helpottaa myös dialogin suunnittelussa: Kun rooli on tarpeeksi selkeä, keskitymme olennaiseen dialogiin emmekä päädy tekemään liian yleistä tai turhaa keskustelupolkua, joka vain hämää loppukäyttäjää botin todellisesta luonteesta ja tarkoituksesta.

Meidän esimerkissämme botille on jo määritelty rooli: Haluamme luoda chatbotin Fiktiivinen Toimistotarvikekauppa Oy:lle, jolla on myymälöitä Jyväskylässä Sepän kauppakeskuksessa ja Lahdessa Karisman kauppakeskuksessa. Toimistotarvikekauppa toimii sopimusasiakkaiden kanssa: tunnemme siis asiakkaamme ja heidän tietonsa voidaan hakea rekisteristä. Toimistotarvikekauppa toimittaa tuotteitaan kolmella päätavalla: Sopimusasiakkaat voivat joko tilata tuotteet toimistoon, kotiin tai halutessaan noutaa ne itse myymälästä.

Toimistotarvikebotin pitäisi siis kyetä avustamaan asiakkaita seuraavissa käyttötarkoituksissa:

\-Tietoa myymälöistä ja niiden sijainnista

\-Tietoa toimitusehdoista ja toimitustavoista

\-Tuotteiden tilaus, ja

\-Tuotetilausten peruutus

Tässä harjoituksessa teemme tarvittavat keskustelut ja dialogit valmiiksi, ja esitämme tilauksen menevän läpi sekä peruutuksen tapahtumisen. Kannattaa kuitenkin huomata, että Watson Assistantin liittäminen olemassa olevaan tilausjärjestelmään on helppoa: koko luomamme keskustelu ja tilaukseen tarvittavat tiedot kulkevat rajapinnan kautta sovellukseen, joten ratkaisu olisi käyttövalmis muutamalla muutoksella.

**Intents**

Intentit ovat esimerkkejä, joilla opetetaan Assistantille, mitä käyttäjän toteamukset saattavat tarkoittaa. Intentin tarkoitus on siis sitoa käyttäjän syöte johonkin tarkoitukseen. Intentien nyrkkisääntö on, että mitä yleisempi, sen parempi. Yhdellä intentillä pitää olla vähintään viisi esimerkkiä, mutta suotava määrä on n. 10-20 esimerkkiä per Intent. Intent erotetaan muista tyypeistä #-etumerkillä

Tätä harjoitusta varten luodaan neljä intentiä ja niiden esimerkit. Luo ensimmäinen syöttämällä käsin seuraavat esimerkit:

**#tietoa\_myymälästä**

`Voitko kertoa teidän myymälöistä?`

`Onko teillä myymälää täällä?`

`Mistä teidät löytää?`

`Missä teidän myymälät ovat?`

`Missä se kauppa on?`

`Missä Lahden kauppa on?`

`Missä Jyväskylän myymälä sijaitsee?`

![](Watson%20Assistant%20Finnish%20Workshop%20v2.0.fld/image004.png)

Loput Intentit ja esimerkit löytyvät valmiiksi tehtyinä kansiosta. Voit tuoda ne bottiisi Import-napilla:

![](Watson%20Assistant%20Finnish%20Workshop%20v2.0.fld/image005.png)

Valitse koneeltasi valmiiksi ladattu .csv-tiedosto:

![](Watson%20Assistant%20Finnish%20Workshop%20v2.0.fld/image006.png)

Tämän jälkeen voit painaa oikeasta yläkulmasta “Try it” ja katsoa, tunnistaako Assistant intentisi oikein. Koska et ole vielä luonut dialogia, Assistant ei vielä vastaa sinulle.

**Entities**

Entity on jokin muuttuja tai objekti, jonka haluat tunnistaa käyttäjän syötteestä. Aikaisemmista esimerkkisyötteistä muun muassa Jyväskylä, Lahti, Paperi ja Kynä ovat meidän kannalta mielekkäitä tunnistettavia. Entityillä voi myös syventää tarkoitusta: voit esimerkiksi tehdä erilaisia dialogeja riippuen, minkälaisen Entityn yhteydessä Intent tunnistetaan.

Entityillä on kolme tasoa: Entityn nimi, Entityn arvo ja synonyymit tai patternit. Näistä Entityn arvoa ja synonyymejä tunnistetaan. Entityn voi halutessaan pitää joko kirjaimellisena (Entityn pitää ilmestyä juuri siinä muodossa kuin kirjoitettu) tai tulkinnanvaraisena (Entity ajetaan NLU-moottorin läpi ja myös osittaiset osumat, kirjoitusvirheet ja taivutusmuodot pyritään tunnistamaan).

            Synonyymien kohdalla käytetään yleensä ns. Fuzzy Matchingiä, ja pyritään tunnistamaan useampi syöte samaksi arvoksi. Suomen kielellä tehtäessä on hyvä kirjoittaa myös muutama taivutusmuoto mukaan.

            Pattern on perinteisempi täydellinen osuma, ja käyttää löyhästi Javan Regular Expressioniin pohjautuvaa syötettä. Voit siis hakea Entityjä myös RegExillä.

Tätä harjoitusta varten luodaan viisi Entityä:

**@Toimitustapa**

**![](Watson%20Assistant%20Finnish%20Workshop%20v2.0.fld/image007.png)**

Löydät kansiosta neljä muuta entityä valmiina, jotka voit tuoda import-toiminnolla bottiisi:

**@Toimistotarvike**

**@Kaupan\_Sijainnit**

**@Kynävaihtoehdot**

Viimeinen muuttujamme(**@Tilausnumero**) on hieman huijausta, sillä tunnistamme tilausnumeron kovakoodattuna Entitynä ilman Fuzzy Matchingiä. Yleisesti tämä tehtäisiin hakemalla taustajärjestelmästä, mutta koska keskitymme harjoituksessa vain botin rakentamiseen, teemme tämän kovakoodattuna arvona:

**Dialog**

Seuraavaksi rakennamme itse keskustelun. Toisin kuin Intentit ja Entityt, Dialog on täysin sääntöpohjainen. Dialog-puu menee aina vaihtoehtoja ylhäältä alaspäin, kunnes se löytää noden, jonka ehdot täyttyvät (Esimerkiksi Jos #tilaus ja @Toimistotarvike:Kynä). Noden sisään mennään vain, jos sen Parent noden ehto on täyttynyt. Dialogin lisäksi on myös Context, johon voidaan tallentaa keskustelun aikana tietoa, kuten käyttäjän nimi, halutut tuotteet tai löydetyt entityt, jotta voidaan seurata keskustelua ja palata jo kerrottuihin asioihin myöhemmin. Itse tehtyjen Intentien ja Entityjen lisäksi on aina kolme valmista tunnistetta: Welcome, anything\_else ja true. Welcome aktivoituu, kun chat aukeaa, ennen käyttäjän syötettä jota tulkita. Anything\_else ja true toteutuvat aina: kun dialogipolussa kohdataan anything\_else, se toteutetaan, ja keskustelu ei etene alempiin nodeihin.

Muutetaan ensin Welcome ja Anything Else- Nodet suomenkieliseen bottiin paremmin sopiviksi:

![](Watson%20Assistant%20Finnish%20Workshop%20v2.0.fld/image008.png)

Anything elsen kohdalla haluamme antaa useamman vaihtoehdon; on mahdollista, että käyttäjä joutuu tähän Nodeen useamman kerran, joten emme halua toistaa samaa lausetta käyttäjälle useasti. Lisäämme myös kehoituksen ottaa yhteyttä asiakaspalvelijaan, jos keskustelu ei näytä etenevän ja joudumme usein myöntämään, ettemme pysty tulkitsemaan syötettä.

![](Watson%20Assistant%20Finnish%20Workshop%20v2.0.fld/image009.png)

Nyt voimme luoda ensimmäisen Noden. Paina Dialog-näkymän ylälaidasta Create Node ja varmista, että se on Welcome- ja Anything Else-noden välissä. Anna Nodelle nimi Toimitusehdot ja kohtaan `If assistant recognizes` hae aikaisemmin luotu #toimitusehdot-intent. ”Then respond with”-kenttään haluamme lisätä tekstin, joka lähetetään, kun aikaisempi ehto toteutuu:

![](Watson%20Assistant%20Finnish%20Workshop%20v2.0.fld/image010.png)

**Useamman tason keskustelu**

Voimme myös luoda keskustelun useammassa tasossa. Aloita luomalla kansio ”Create folder”-napista. Määrittele kansiolle nimeksi ”Myymälätiedot” ja ”If assistant recognizes”-kenttään #tietoa\_myymälästä-Intent. Seuraavaksi paina kansion oikeassa nurkassa olevaa kolmea pistettä ja valitse ”Add node to folder”. Anna Nodelle nimeksi ”Jyväskylän myymälä” ja määritä ehdoksi Entity ”@Kaupan\_Sijainnit:Jyväskylä”:

![](Watson%20Assistant%20Finnish%20Workshop%20v2.0.fld/image011.png)

Tee sama Lahden myymälätiedot-nimiselle Nodelle:

![](Watson%20Assistant%20Finnish%20Workshop%20v2.0.fld/image012.png)

Voimme myös luoda Noden, joka kysyy tarkentavia kysymyksiä ja palautuu alkuperäiseen vaiheeseen. Tämä Node aktivoituu, mikäli kansion ehto täytyy, mutta sopivaa seuraavaa ehtoa ei löydy. Lisää uusi node kansioon, laita ehdoksi Anything else ja lisää tarkentava kysymys. Selaa Noden valikon loppuun ja valitse ”And finally -> Jump to” Valitse Jump to-kohdaksi kansion ensimmöinen Node, Jyväskylän myymälätiedot:

![](Watson%20Assistant%20Finnish%20Workshop%20v2.0.fld/image013.png)

Kansion lopullisen rakenteen pitäisi näyttää tältä:

![](Watson%20Assistant%20Finnish%20Workshop%20v2.0.fld/image014.png)

**Käyttäjän syötteiden kerääminen yhdessä Nodessa**

Seuraavaksi luomme uudenlaisen Noden: Slots. Slots-node antaa mahdollisuuden kerätä useammman syötteen samalla kertaa ja tallentamaan sen Contextiin ilman pitkää keskustelupolkua. Luo uusi node samalla tavalla, avaa se ja paina Customize oikeassa yläkulmassa. Valitse Slots ja Multiple responses aktiiviseksi:

![](Watson%20Assistant%20Finnish%20Workshop%20v2.0.fld/image015.png)

Seuraavaksi voimme tehdä Slotit. Slotit sisältävät kolme kenttää: Entity, joka pitää löytyä, Context, johon arvo tallennetaan, ja syöte, joka lähetetään käyttäjälle, mikäli Entityä ei löydy käyttäjän toteamuksesta:

![](Watson%20Assistant%20Finnish%20Workshop%20v2.0.fld/image016.png)

Tämän lisäksi aktivoimme kentän ”Multiple responses”. Tämä mahdollistaa meidän räätälöimään syötteemme aikaisemmin kerätyn syötteen perusteella, tässä tapauksessa toimistotarvikkeen perusteella. Entityn sijaan haluamme katsoa, olemmeko onnistuneesti tallentaneet tarvikkeen Context-muuttujaksi:

![](Watson%20Assistant%20Finnish%20Workshop%20v2.0.fld/image017.png)

Painamalla ratasikonia voimme muokata vastausta kuten muitakin Nodeja. Huomaa, että voimme viitata käyttäjän aikaisempaan syötteeseen hakemalla sen Contextista tai syötteestä. Tässä tapauksessa haluamme vahvistaa käyttäjän valitseman toimitustavan vastauksessamme:

![](Watson%20Assistant%20Finnish%20Workshop%20v2.0.fld/image018.png)

Voimme halutessamme tehdä myös monimutkaisempia valintoja. Tässä tapauksessa valikoimassamme on useampia kyniä, joita tarjoamme asiakkaalle Option-vaustauksen muodossa.

Avaa $Toimistotarvike-ehdon vastausvaihtoehto ratasikonista, ja muuta se palauttamaan Text- ja Option responset:

![](Watson%20Assistant%20Finnish%20Workshop%20v2.0.fld/image019.png)

Nyt annamme käyttäjälle useamman kynävaihtoehdon, mutta emme tallenna tietoa mihinkään. Tätä varten meidän pitää luoda uusi Child Node tämän vastauksen alle:

![](Watson%20Assistant%20Finnish%20Workshop%20v2.0.fld/image020.png)

Lisää kynävaihtoehtoon uuden valintaikkunamme mukaiset Entityt ja sopiva vastaus:

![](Watson%20Assistant%20Finnish%20Workshop%20v2.0.fld/image021.png)

**Keskustelusta poikkeaminen**

Käyttäjämme saattaa haluta kysellä myymälän sijainteja tai toimitusehtoja myös tilauksen aikana. Tämä on mahdollista Digressions-ominaisuuden ansiosta, jolloin voimme käydä toisessa keskustelupolussa ja palata takaisin samaan paikkaan, josta kysely aloitettiin. Aktivoidaan tämä kansiollemme painamalla Customize-nappia ja aktivoimalla Digressions- sekä return after digression-valinnat:

![](Watson%20Assistant%20Finnish%20Workshop%20v2.0.fld/image022.png)

Tämän lisäksi Slots-nodessa pitää aktivoida mahdollisuus poiketa kesken kyselyn. Avaa Tilaus-noden Customize-ikkuna, valitse Digressions ja aktivoi mahdollisuus:

![](Watson%20Assistant%20Finnish%20Workshop%20v2.0.fld/image023.png)

Lopuksi haluamme vielä rakentaa vielä tilauksen peruutusmahdollisuuden. Tämä käy helposti kahdella sisäkkäisellä nodella: ensimmäisessä vahvistetaan kysyjän halu peruuttaa tilaus sekä kysytään tilausnumeroa. Toisessa katsotaan, vastaako käyttäjän syöte tunnettuja tilausnumeroita:

![](Watson%20Assistant%20Finnish%20Workshop%20v2.0.fld/image024.png)

![](Watson%20Assistant%20Finnish%20Workshop%20v2.0.fld/image025.png)

![](Watson%20Assistant%20Finnish%20Workshop%20v2.0.fld/image026.png)

**Loppu**

Onneksi olkoon, nyt sinulla pitäisi olla valmis tilausbotti. Voit painaa ”Try it”-nappia ja leikkiä botilla, tai kokeilla rakentaa lisää tilausvaihtoehtoja. Kokeile myös Assistant-välilehdeltä bottisi julkaisuvaihtoehtoja.
