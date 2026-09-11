const test=require('node:test');const assert=require('node:assert/strict');
const {verificationEmail}=require('../lib/partnerVerificationEmail');
const {invitationInstructions}=require('../lib/testerInvitationEmail');
const {createResendMailAdapter}=require('../lib/partnerAccessResendMail');
const sample='482931';
test('verification email uses approved branding, inline logo, clear code and plain fallback without CTA',()=>{
 const m=verificationEmail({code:sample,expiresInSeconds:600});
 for(const content of [m.html,m.text]) {
  assert.ok(content.includes(sample));assert.equal(content.split(sample).length-1,1);
  assert.ok(content.includes('10 minutes'));
 }
 for(const s of ['Your verification code','support@heyzippi.com','The Zippi Team','Zippi Technologies']) assert.ok(m.html.includes(s));
 assert.ok(!m.subject.includes(sample));assert.match(m.html,/cid:zippi-bunny/);
 assert.deepEqual(m.attachments,invitationInstructions('ios', 'qa@example.test').attachments);
 assert.doesNotMatch(m.html,/<script|<form|<iframe|src="http|Get TestFlight|v:roundrect/i);
 assert.match(m.html,/#303033/);assert.match(m.html,/#e7b858/);
 assert.doesNotMatch(m.html, /INVITED_EMAIL|qa@example\.test/);
});
test('expiry reflects unchanged supplied lifetime and interpolated text is HTML escaped',()=>{
 assert.match(verificationEmail({code:sample,expiresInSeconds:300}).text,/5 minutes/);
 assert.doesNotMatch(verificationEmail({code:'<img onerror="test">',expiresInSeconds:600}).html,/<img onerror/);
});
test('OTP delivery includes HTML, fallback and logo only in the intended email body; no logs',async()=>{
 let sent;const logs=[];const originals={};
 for(const key of ['log','warn','error','debug']){originals[key]=console[key];console[key]=(...args)=>logs.push(args);}
 try {
  const mail=createResendMailAdapter({RESEND_API_KEY:'test-only-key',ZIPPI_PARTNER_EMAIL_FROM:'Zippi <preview@example.test>'},{fetchImpl:async(url,opts)=>{sent={url,...opts};return {ok:true,json:async()=>({id:'test-id'})};}});
  await mail.send({email:'qa@example.test',code:sample,expiresInSeconds:600});
 }finally{for(const key of Object.keys(originals))console[key]=originals[key];}
 assert.equal(logs.length,0);assert.equal(sent.url,'https://api.resend.com/emails');
 assert.ok(!JSON.stringify(sent.headers).includes(sample));
 const body=JSON.parse(sent.body);assert.deepEqual(body.to,['qa@example.test']);
 assert.ok(body.html.includes(sample));assert.ok(body.text.includes(sample));
 assert.equal(body.attachments[0].content_id,'zippi-bunny');
});

test('leading zeros stay visible and an unusual code cannot escape its HTML text slot',()=>{
 const m=verificationEmail({code:'001234',expiresInSeconds:600});
 assert.match(m.html,/>001234<\/td>/);assert.match(m.text,/001234/);
 const unsafe=verificationEmail({code:'<>&"\'',expiresInSeconds:600});
 assert.ok(unsafe.html.includes('&lt;&gt;&amp;&quot;&#39;'));
});
test('branded delivery does not disclose code in a provider-failure exception or logs',async()=>{
 const logs=[],old=console.error;console.error=(...args)=>logs.push(args);
 try{
  const mail=createResendMailAdapter({RESEND_API_KEY:'test-only-key',ZIPPI_PARTNER_EMAIL_FROM:'Zippi <preview@example.test>'},{fetchImpl:async()=>{throw new Error('private OTP '+sample);}});
  await assert.rejects(mail.send({email:'qa@example.test',code:sample,expiresInSeconds:600}),e=>{
   assert.equal(e.code,'mail_unavailable');assert.ok(!JSON.stringify(e).includes(sample));assert.ok(!e.message.includes(sample));return true;
  });
 }finally{console.error=old;}
 assert.equal(logs.length,0);
});
