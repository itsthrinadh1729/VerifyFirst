declare var chrome: any;
declare namespace chrome {
  export namespace runtime {
    export interface MessageSender {
      tab?: any;
    }
  }
}
