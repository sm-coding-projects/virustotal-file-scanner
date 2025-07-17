"""
Tests for the security measures implemented in the application.
"""
import pytest
import json
import time
from unittest.mock import patch, MagicMock
from flask import url_fore
from backend.utils.security import (
    sanitize_input, sanitize_dict, validate_uuid, 
    rate_limit, validate_content_type, secure_headers,
 re
)

def test_sanitize_input():
    """Test input sanitizatio""
    # Test basic sanitization
    '
    
    # Test dangerous URL schemes
    assert 'javascript:' not in sanitize_input('javascript:alert(1)')
    cript>')
    
    # Test non-string input
    assert sanitize_input(123) == 123
 None

def test_sanitize_dict():
    """Test dictionary sanitization funct""
    # Test nestedn
    test_dict = {
        'name': '<sipt>',
        'nested': {
          1)'
        },
        'list': ['<im,
     3
    
    
    t)
    
    assert sanitized['name'] == '&lt;script&gt;alert(&quot;Xt&gt;'
    assert 'javascript:' not in sanitized['nested']['value']
    assert sanitized['list'][0] == '&lt;img src=
    assert sanitized['list'][1] == 'n
    123
    
    # Test non-dict input
    assert sanitize_dict('string') == ing'


def test_validate_uuid():
    """Test UUID """
    # Valid UUIDs
    assert validate_uuid('123e4567-e89b-12d3-a456-426614174000') is True
    
    
    # Invalid UUIDs
    assert validate_uuid('not-a-uuid') is False
    assert validate_uuid('123e4567-e89b-12d3-a456') is False
    assert validate_uuid('123e4567-e89be
    assert validate_uuid(None) is False
e

def test_secure_headers():
    """Test security headers f
    ()
    
    # Check that all expected security headers 
    assert 'Content-Security-Policy' in headers
    assert 'X-Content-Type-Options' in eaders
    assert 'X-Frame-Options' in headers
    assert 'X-XSS-Protection' in headers
    assert 'Strict-Transport-Security' ers
    
    
    # Check specific values
    assert headers['X-Content-Type-Options'] ==iff'
    assert headers['X-Frame-Options'] == 'DENY'sert 'max-age=31536000'
"""== 'DENYns'] Frame-Optioheaders['X-result.sert ders
    as.heaultesns' in rptiome-O 'X-Fra
    asserteaderslt.hresuns' in -Type-Optioentert 'X-Cont  asseaders
  ult.h res-Policy' inent-Securityrt 'Cont   assedded
 ers were ack that head 
    # Chesponse)
   ddleware(relt = miesu
    rddleware()eaders_mity_hurisecddleware = re
    middlewa the mipply# A    
    "Test")
 Response(se =responponse
     mock res# Create a    are."""
dlews midy headerritTest secu    """app):
leware(idders_mady_heritcutest_seef ror']

derata['in der' t-Type headid Content 'Inval     assern data
   ' irort 'er     asserdata)
   onse[0]..loads(respata = json     d   == 415
 esponse[1]assert r   le)
     ponse, tupce(resanssert isinst)
        aion( test_functe =spons        reld fail
ype shout content t incorrecequest with        # Rl'):
ation/xmlic'appt_type=   conten                            ",
  </xml>l>  data="<xm                            
   d='POST', est', metho'/test_context(equtest_rp.    with ap  
"
  == "OKonse assert resp       ction()
 funt_onse = tes    respucceed
    hould stent type s conith correctest w# Requ  
        "
       "OK   return       ion():
  test_funct   def 
     )ion/json'applicatt_type('e_conten  @validat     on
  validaticontent typetion with unc feate a test   # Cr
     n/json'):applicatiotype='tent_       con                     
     }),data'{'test': 'ps(a=json.dum  dat                         , 
      od='POST'meth, t('/test'quest_contex app.test_re"
    with""n decorator.idationt type valte"Test con ""):
   pe(app_content_tyst_validate

def ter' in data_aftetrysert 're     as']
   orta['erreded' in da exce'Rate limit    assert 
    data' in sert 'error      as  )
ataponse[0].desads(r = json.lota        da== 429
se[1] pon assert res
       tion()= test_func  response sts
       Many Reque 429 Toofail withest should Third requ #   
        '0'
      =='] ngimit-Remaini-RateLe[2]['Xrt respons      asse] == 200
  e[1sert respons
        as == "OK" response[0]   assertn()
     functio= test_   response      succeed
ld  shoucond request        # Se   
'
     g'] == '1aininRemimit-ateL]['X-Rt response[2asser2'
         '] ==Limit'X-RateLimit-][' response[2 assert]
       ponse[2 resinmit' teLimit-LiX-Ra    assert '    = 200
 =e[1]onsert respass        == "OK"
esponse[0]    assert rle)
     esponse, tup(rsinstance    assert i  ()
  on test_functiresponse =  eed
       succuest shouldFirst req #             
  "OK"
      return 
       ):t_function(  def tes)
      per_minute=2quests_t(re @rate_limi       iting
ate lim with rfunctionest # Create a t
        ('/test'):st_contextt_requetesth app.""
    wiecorator."imiting dt rate les"""T
    app):mit(st_rate_lidef te
ecurity']
port-Srict-Transeaders['St' in h
    as