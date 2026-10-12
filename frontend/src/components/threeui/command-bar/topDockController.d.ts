export type TopDockOptions = {
  proximity: number;
  spring: number;
  damping: number;
  widthGrowth: number;
  heightGrowth: number;
  drop: number;
  axis?: 'x' | 'y';
  distribute?: boolean;
  lockTrack?: boolean;
};

/** Starts the dock physics on `nav`; returns a function that stops it. */
export declare function createTopDockController(nav: HTMLElement, options: () => TopDockOptions): () => void;
