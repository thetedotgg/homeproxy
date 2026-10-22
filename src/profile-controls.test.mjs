import assert from "node:assert/strict";
import test from "node:test";
import {parseTime,parsePrivateIps,createProfile,validProfiles} from "../target/ui-tests/profile-controls.js";

test("manual identities accept canonical private IPs without duplicates",()=>{
  assert.deepEqual(parsePrivateIps("192.168.1.2, 10.1.2.3"),["192.168.1.2","10.1.2.3"]);
  assert.deepEqual(parsePrivateIps(""),[]);
  for(const value of ["8.8.8.8","127.0.0.1","192.168.1.256","192.168.01.2","10.0.0.1 10.0.0.1"])assert.equal(parsePrivateIps(value),null);
});
test("schedule times use exact valid minutes including an overnight boundary",()=>{
  assert.equal(parseTime("00:00"),0);assert.equal(parseTime("23:59"),1439);assert.equal(parseTime("07:30"),450);
  for(const time of ["7:30","24:00","23:60","","00:0x"])assert.equal(parseTime(time),null);
});
test("profile forms preserve unique authenticated identities and IP ownership",()=>{
  const profile=createProfile();profile.name="Test TV";profile.ips=["192.168.1.2"];
  assert.equal(validProfiles([profile],"household"),true);
  assert.equal(validProfiles([{...profile,username:"bad.name"}],"household"),false);
  assert.equal(validProfiles([{...profile,password:"short"}],"household"),false);
  const another=createProfile();another.name="Other";another.ips=["192.168.1.2"];
  assert.equal(validProfiles([profile,another],"household"),false);
  assert.equal(validProfiles([{...profile,username:"household"}],"household"),false);
  assert.equal(validProfiles([{...profile,schedules:[{days:[1],startMinute:0,endMinute:0,action:"deny",uploadBytesPerSecond:0,downloadBytesPerSecond:0}]}],"household"),false);
});
