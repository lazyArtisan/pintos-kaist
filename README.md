Brand new pintos for Operating Systems and Lab (CS330), KAIST, by Youngjin Kwon.

The manual is available at https://casys-kaist.github.io/pintos-kaist/.

---

### 프로젝트 설명

> Pintos-kaist는 x86-64 아키텍처용 간단한 운영체제 프레임워크다. <br>
> 이 프로젝트는 스탠퍼드 대학교의 Pintos 프로젝트를 포크한 것이다. <br>
> 이후부터는 ‘pintos-kaist’ 대신 ‘Pintos’라 부르겠다. <br>
> Pintos는 커널 스레드, 사용자 프로그램의 로딩 및 실행, 파일 시스템을 지원하지만, 이 모든 기능을 매우 단순한 방식으로 구현하고 있다. <br>
> Pintos 프로젝트에서 여러분과 팀은 이 세 영역의 기능을 강화하게 된다. <br>

- 부트캠프 '크래프톤 정글'에서 35일 (24.08.22 ~ 24.10.02) 동안 진행한 프로젝트
- Chapter 1 : 쓰레드 강제 전환, 쓰레드 스케줄러 구현
- Chapter 2 : 호출 규약대로 정해진 메모리 주소에 프로그램 실행 명령줄 파싱하여 전달, 시스템 콜 구현
- Chapter 3 : 페이지 폴트 이후 물리 메모리 주소를 가져오는 과정 구현

<br>

### Chapter 1 : Threads

>이번 과제에서는 기본적인 기능만 갖춘 스레드 시스템이 제공된다. <br>
>여러분의 임무는 이 시스템의 기능을 확장하여 동기화(synchronization) 문제를 더 깊이 이해하는 것이다. <br>

<details>    
  <summary>발표 PPT</summary>    
  <p>
    <img width="1135" height="426" alt="Image" src="https://github.com/user-attachments/assets/0d3dfd89-ff6f-4f00-a6c7-7d4d3a703811" />

<img width="975" height="513" alt="Image" src="https://github.com/user-attachments/assets/9e29df2c-7372-47be-af81-cd53476a5253" />

<img width="1078" height="464" alt="Image" src="https://github.com/user-attachments/assets/d8bfeb0f-944c-49d1-9c73-d37cfbf3c63c" />

<img width="975" height="513" alt="Image" src="https://github.com/user-attachments/assets/fc5067ff-d531-4649-be5a-cd436097393e" />

<img width="971" height="515" alt="Image" src="https://github.com/user-attachments/assets/59c24dc1-1f3c-4151-b66c-3b80ff142775" />

<img width="1174" height="426" alt="Image" src="https://github.com/user-attachments/assets/00485079-8476-46ad-bf3b-a13797f243fc" />

<img width="1013" height="494" alt="Image" src="https://github.com/user-attachments/assets/18228496-0d7b-44d6-b380-4f098a72d512" />

<img width="997" height="502" alt="Image" src="https://github.com/user-attachments/assets/a137c6e2-bbaa-4149-b3fe-3aeb9f0f8cb8" />

<img width="1037" height="482" alt="Image" src="https://github.com/user-attachments/assets/48558618-02e2-4034-832a-dc30252cd8ab" />

<img width="1067" height="469" alt="Image" src="https://github.com/user-attachments/assets/ae08471d-c12b-4f68-980a-4f880be1b17a" />

<img width="976" height="513" alt="Image" src="https://github.com/user-attachments/assets/2a0ad7fb-6372-47d0-b4e9-1a9980549e95" />

<img width="1047" height="478" alt="Image" src="https://github.com/user-attachments/assets/4c63caed-ebcc-43c6-9fc3-5ac08fc5e2bb" />

<img width="1172" height="426" alt="Image" src="https://github.com/user-attachments/assets/c90026d3-2d7f-4ec7-bbc4-0ed948211654" />

<img width="1009" height="495" alt="Image" src="https://github.com/user-attachments/assets/bff6bfad-68b7-43fc-9f6e-12872edb0e28" />

<img width="1040" height="481" alt="Image" src="https://github.com/user-attachments/assets/27cf9143-3175-4a93-a6cb-54d9deeb8005" />

<img width="1012" height="494" alt="Image" src="https://github.com/user-attachments/assets/95a83f32-bb68-4140-ae9f-f338a3dd0641" />

<img width="944" height="530" alt="Image" src="https://github.com/user-attachments/assets/70fbf411-f137-4f4a-a011-2d36bb7f3cec" />

<img width="1099" height="455" alt="Image" src="https://github.com/user-attachments/assets/a350fdb7-8312-406e-9a7f-442fb15c99ee" />
  </p>
</details>

쓰레드 강제 전환
- 우선순위가 더 높은 쓰레드가 이미 실행되고 있던 쓰레드를 밀어내고 실행되게 해야 했음     
- 새로운 쓰레드가 추가되거나, 우선순위가 변경되면 쓰레드 대기 리스트를 우선순위대로 정렬     
- 그 후 실행 중인 쓰레드가 리스트 맨 앞 쓰레드의 우선순위보다 낮으면 쓰레드 교체

우선순위 기부
- 우선순위가 높아도, 필요한 자원을 보유하고 있는 쓰레드의 우선순위가 낮으면 밀어내기 불가     
- 자신이 필요한 자원을 가진 쓰레드에게 우선순위를 기부하여 먼저 진행되게 하는 로직 적용

쓰레드 스케줄러
- 실행 중인 쓰레드는 우선순위 낮추고, 대기 중인 쓰레드는 우선순위 높이는 스케줄러 도입



<br>

### Chapter 2 : User Program

> 이제 Pintos의 구조와 스레드 패키지에 익숙해졌다면, 사용자 프로그램을 실행할 수 있도록 하는 시스템의 일부를 구현할 차례다. <br>
> 기본 코드에는 이미 사용자 프로그램을 로드하고 실행하는 기능이 포함되어 있지만, 현재는 입출력(I/O)이나 상호작용 기능이 전혀 없다. <br>
> 이번 프로젝트에서는 프로그램이 시스템 호출(System Call) 을 통해 운영체제와 상호작용할 수 있도록 구현해야 한다. <br>

- 시스템 콜 구현

<br>

### Chapter 3 : Virtual Memory

>현재 여러분의 운영체제는 올바른 동기화(synchronization) 를 통해 여러 실행 스레드를 관리할 수 있으며, 여러 사용자 프로그램을 동시에 로드하고 실행할 수도 있다. <br>
>그러나 실행 가능한 프로그램의 개수와 크기는 시스템의 주 메모리(main memory) 용량에 의해 제한된다. <br>
>이번 과제에서는 이러한 제한을 제거하고, ‘무한한 메모리(infinite memory)’가 존재하는 것처럼 보이게 하는 기능을 구현해야 한다. <br>

- 보조 페이지 테이블을 만들어 기존 페이지 테이블을 페이징으로 나눔
- 프레임 테이블로 각 프레임에 대한 정보를 저장
- 페이지 폴트가 일어나면 프레임을 확보하여 가상 주소를 매핑



