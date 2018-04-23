import geoip2.database
# Waaay inefficient to query the DB 3 times for 3 details.
# Locate should just return errything

def locate(ip):
    try:
      reader = geoip2.database.Reader('GeoLite2-City.mmdb')
      response = reader.city(ip)

      coord = ( response.location.latitude, response.location.longitude )
    except:
        return '-'

    return coord

def city(ip):
    try:
        reader = geoip2.database.Reader('GeoLite2-City.mmdb')
        response = reader.city(ip)
        citta = response.city.name
    except:
        return '-'
    return citta

def country(ip):
    try:
        reader = geoip2.database.Reader('GeoLite2-City.mmdb')
        response = reader.city(ip)
        stato = response.country.name
    except:
        return '-'
    return stato
