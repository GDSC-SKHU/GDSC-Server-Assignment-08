### postman

- **사용자가 admin 권한**
  - login(admin) : 로그인하여 admin의 토큰 생성
  - user(admin) : user 페이지에 admin 접속 가능
  - admin(admin) : admin 페이지에 admin 접근 o
  - main(admin) : main 페이지에 admin 권한 접근 o

    
- **사용자가 user 권한**
  - login(user) : 로그인하여 user의 토큰 생성
  - user(user) : user 페이지에 user 권한으로 접근
  - admin(user) : 403 Forbidden error 발생 -> 접근 권한 없음.
  - main(user) : 권한이 없어도 접근이 가능함. 