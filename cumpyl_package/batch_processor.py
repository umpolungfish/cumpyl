import os
import sys
import glob
import threading
import queue
import time
from typing import List, Dict, Any, Callable, Optional
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.progress import Progress, TaskID, TextColumn, BarColumn, TimeElapsedColumn, TimeRemainingColumn
from rich.panel import Panel
from rich.table import Table
from .config import ConfigManager
from .cumpyl import BinaryRewriter


class BatchJob:
    """𐑮𐑧𐑐𐑮𐑦𐑟𐑧𐑯𐑑𐑟 𐑩 𐑕𐑦𐑙𐑜𐑩𐑤 𐑓𐑲𐑤 𐑦𐑯 𐑩 𐑚𐑨𐑗 𐑪𐑐𐑼𐑱𐑖𐑩𐑯"""
    
    def __init__(self, input_file: str, output_file: str = None, operations: List[Dict[str, Any]] = None):
        self.input_file = input_file
        self.output_file = output_file or self._generate_output_filename(input_file)
        self.operations = operations or []
        self.status = "pending"  # pending, processing, completed, failed
        self.error = None
        self.start_time = None
        self.end_time = None
        self.results = {}
    
    def _generate_output_filename(self, input_file: str) -> str:
        """𐑜𐑧𐑯𐑼𐑱𐑑 𐑩 𐑛𐑦𐑓𐑷𐑤𐑑 𐑬𐑑𐑐𐑫𐑑 𐑓𐑲𐑤𐑯𐑱𐑥"""
        path = Path(input_file)
        return str(path.parent / f"processed_{path.name}")
    
    def add_operation(self, operation_type: str, **kwargs):
        """𐑨𐑛 𐑩 𐑯𐑩𐑩𐑛 𐑪𐑐𐑼𐑱𐑖𐑩𐑯 𐑑 𐑞𐑦𐑕 𐑡𐑪𐑚"""
        self.operations.append({
            'type': operation_type,
            'params': kwargs
        })
    
    def get_duration(self) -> float:
        """𐑜𐑧𐑑 𐑞 𐑛𐑘𐑫𐑼𐑱𐑖𐑩𐑯 𐑝 𐑞𐑦𐑕 𐑡𐑪𐑚 𐑦𐑯 𐑕𐑧𐑒𐑩𐑯𐑛𐑟"""
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        elif self.start_time:
            return time.time() - self.start_time
        return 0.0


class BatchProcessor:
    """𐑞 𐑥𐑱𐑯 𐑚𐑨𐑗 𐑐𐑮𐑩𐑕𐑧𐑕𐑦𐑙 𐑦𐑯𐑡𐑦𐑯"""
    
    def __init__(self, config: ConfigManager):
        self.config = config
        self.console = Console()
        self.jobs: List[BatchJob] = []
        self.completed_jobs: List[BatchJob] = []
        self.failed_jobs: List[BatchJob] = []
        
        # 𐑞𐑮𐑧𐑛 𐑐𐑵𐑤 𐑒𐑪𐑯𐑓𐑦𐑜
        self.max_workers = self.config.performance.max_worker_threads if self.config.performance.enable_parallel_processing else 1
        self.progress_queue = queue.Queue()
    
    def add_files(self, file_patterns: List[str], recursive: bool = True) -> int:
        """𐑨𐑛 𐑓𐑲𐑤𐑟 𐑚𐑱𐑕𐑑 𐑪𐑯 𐑜𐑤𐑪𐑚 𐑐𐑨𐑑𐑼𐑯𐑟"""
        added_count = 0
        
        for pattern in file_patterns:
            if recursive and '**' not in pattern:
                # 𐑨𐑛 𐑮𐑦𐑒𐑻𐑕𐑦𐑝 𐑜𐑤𐑪𐑚 𐑦𐑓 𐑯𐑪𐑑 𐑩𐑤𐑮𐑧𐑛𐑦 𐑦𐑯𐑒𐑤𐑿𐑛𐑦𐑛
                pattern = os.path.join(os.path.dirname(pattern) or '.', '**', os.path.basename(pattern))
            
            # 𐑿𐑟 glob 𐑑 𐑓𐑲𐑯𐑛 𐑥𐑨𐑗𐑦𐑙 𐑓𐑲𐑤𐑟
            for filepath in glob.glob(pattern, recursive=recursive):
                if os.path.isfile(filepath):
                    # 𐑗𐑧𐑒 𐑦𐑓 𐑓𐑲𐑤 𐑕𐑲𐑟 𐑦𐑟 𐑩𐑒𐑕𐑧𐑐𐑑𐑩𐑚𐑩𐑤
                    file_size_mb = os.path.getsize(filepath) / (1024 * 1024)
                    if file_size_mb <= self.config.framework.max_file_size_mb:
                        job = BatchJob(os.path.abspath(filepath))
                        self.jobs.append(job)
                        added_count += 1
                    else:
                        if self.config.framework.verbose_logging:
                            self.console.print(f"[yellow]Skipping {filepath}: too large ({file_size_mb:.1f}MB)[/yellow]")
        
        return added_count
    
    def add_directory(self, directory: str, file_extensions: List[str] = None, recursive: bool = True) -> int:
        """𐑨𐑛 𐑷𐑤 𐑓𐑲𐑤𐑟 𐑦𐑯 𐑩 𐑛𐑲𐑮𐑧𐑒𐑑𐑼𐑦"""
        if not os.path.isdir(directory):
            raise ValueError(f"Directory does not exist: {directory}")
        
        # 𐑛𐑦𐑓𐑷𐑤𐑑 𐑧𐑒𐑕𐑧𐑒𐑿𐑑𐑩𐑚𐑩𐑤 𐑦𐑒𐑕𐑑𐑧𐑯𐑖𐑩𐑯𐑟
        if file_extensions is None:
            file_extensions = ['.exe', '.dll', '.so', '.bin', '.out', '']  # 𐑧𐑥𐑐𐑑𐑦 𐑕𐑑𐑮𐑦𐑙 𐑓𐑹 𐑓𐑲𐑤𐑟 𐑢𐑦𐑞𐑬𐑑 𐑦𐑒𐑕𐑑𐑧𐑯𐑖𐑩𐑯
        
        patterns = []
        for ext in file_extensions:
            if ext:
                pattern = os.path.join(directory, f"*{ext}")
            else:
                # 𐑓𐑹 𐑓𐑲𐑤𐑟 𐑢𐑦𐑞𐑬𐑑 𐑦𐑒𐑕𐑑𐑧𐑯𐑖𐑩𐑯, 𐑢𐑰 𐑯𐑰𐑛 𐑑 𐑗𐑧𐑒 𐑦𐑯𐑛𐑦𐑝𐑦𐑛𐑘𐑫𐑩𐑤𐑦
                pattern = os.path.join(directory, "*")
            patterns.append(pattern)
        
        return self.add_files(patterns, recursive)
    
    def configure_operation(self, operation_type: str, **kwargs):
        """𐑒𐑩𐑯𐑓𐑦𐑜 𐑩 𐑯 𐑪𐑐𐑼𐑱𐑖𐑩𐑯 𐑑 𐑚𐑰 𐑩𐑐𐑤𐑲𐑛 𐑑 𐑷𐑤 𐑡𐑪𐑚𐑟"""
        for job in self.jobs:
            job.add_operation(operation_type, **kwargs)
    
    def _process_single_job(self, job: BatchJob) -> BatchJob:
        """𐑐𐑮𐑩𐑕𐑧𐑕 𐑩 𐑕𐑦𐑙𐑜𐑩𐑤 𐑡𐑪𐑚"""
        job.status = "processing"
        job.start_time = time.time()
        
        try:
            # 𐑦𐑯𐑦𐑖𐑩𐑤𐑲𐑟 𐑞 𐑚𐑲𐑯𐑩𐑮𐑦 𐑮𐑰𐑮𐑲𐑑𐑼
            rewriter = BinaryRewriter(job.input_file, self.config)
            
            if not rewriter.load_binary():
                raise Exception(f"Failed to load binary: {job.input_file}")
            
            # 𐑤𐑴𐑛 𐑐𐑤𐑳𐑜𐑦𐑯𐑟 𐑦𐑓 𐑯𐑪𐑑 𐑛𐑦𐑟𐑱𐑚𐑩𐑤𐑛
            if self.config.plugins.enabled:
                rewriter.load_plugins()
            
            # 𐑩𐑐𐑤𐑲 𐑰𐑗 𐑪𐑐𐑼𐑱𐑖𐑩𐑯
            for operation in job.operations:
                op_type = operation['type']
                params = operation['params']
                
                if op_type == 'analyze_sections':
                    rewriter.analyze_sections()
                    job.results['section_analysis'] = True
                
                elif op_type == 'plugin_analysis':
                    analysis_results = rewriter.run_plugin_analysis()
                    job.results['plugin_analysis'] = analysis_results
                
                elif op_type == 'encode_section':
                    section_name = params['section_name']
                    encoding = params.get('encoding', 'base64')
                    offset = params.get('offset', 0)
                    length = params.get('length', None)
                    
                    # 𐑦𐑒𐑕𐑑𐑮𐑨𐑒𐑑 𐑯 𐑦𐑯𐑒𐑴𐑛 𐑞 𐑕𐑧𐑒𐑖𐑩𐑯
                    from .cumpyl import EncodingPlugin
                    encoding_plugin = EncodingPlugin()
                    
                    section_data = rewriter.get_section_data(section_name)
                    if not length or length > len(section_data) - offset:
                        length = len(section_data) - offset
                    
                    encoded_data = encoding_plugin.encode_section_portion(
                        rewriter, section_name, offset, length, encoding
                    )
                    
                    if encoded_data:
                        # 𐑩𐑐𐑤𐑲 𐑞 𐑦𐑯𐑒𐑴𐑛𐑦𐑙 𐑑 𐑞 𐑚𐑲𐑯𐑩𐑮𐑦
                        encoded_bytes = encoded_data.encode('utf-8')
                        original_data_portion = section_data[offset:offset+length]
                        
                        if len(encoded_bytes) > len(original_data_portion):
                            encoded_bytes = encoded_bytes[:len(original_data_portion)]
                        elif len(encoded_bytes) < len(original_data_portion):
                            encoded_bytes += b'\x00' * (len(original_data_portion) - len(encoded_bytes))
                        
                        rewriter.modify_section_data(section_name, offset, encoded_bytes)
                        job.results[f'encoded_{section_name}'] = {
                            'encoding': encoding,
                            'offset': offset,
                            'length': length,
                            'success': True
                        }
                
                elif op_type == 'custom':
                    # 𐑩𐑤𐑬 𐑓𐑹 𐑒𐑳𐑕𐑑𐑩𐑥 𐑪𐑐𐑼𐑱𐑖𐑩𐑯𐑟
                    custom_func = params.get('function')
                    if custom_func and callable(custom_func):
                        result = custom_func(rewriter, job, params)
                        job.results['custom'] = result
            
            # 𐑕𐑱𐑝 𐑞 𐑮𐑦𐑟𐑳𐑤𐑑
            if rewriter.save_binary(job.output_file):
                job.status = "completed"
                job.results['output_file'] = job.output_file
            else:
                raise Exception("Failed to save modified binary")
        
        except Exception as e:
            job.status = "failed"
            job.error = str(e)
            if self.config.framework.debug_mode:
                import traceback
                job.error += f"\n{traceback.format_exc()}"
        
        finally:
            job.end_time = time.time()
        
        return job
    
    def process_all(self, progress_callback: Callable = None) -> Dict[str, Any]:
        """𐑐𐑮𐑩𐑕𐑧𐑕 𐑷𐑤 𐑡𐑪𐑚𐑟 𐑦𐑯 𐑞 𐑒𐑿"""
        if not self.jobs:
            return {
                'completed': 0,
                'failed': 0,
                'total': 0,
                'duration': 0.0
            }
        
        start_time = time.time()
        
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("({task.completed}/{task.total})"),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            console=self.console
        ) as progress:
            
            task = progress.add_task(
                f"Processing {len(self.jobs)} files...",
                total=len(self.jobs)
            )
            
            if self.max_workers == 1:
                # 𐑕𐑦𐑙𐑜𐑩𐑤-𐑞𐑮𐑧𐑛𐑦𐑛 𐑐𐑮𐑩𐑕𐑧𐑕𐑦𐑙
                for job in self.jobs:
                    processed_job = self._process_single_job(job)
                    
                    if processed_job.status == "completed":
                        self.completed_jobs.append(processed_job)
                    else:
                        self.failed_jobs.append(processed_job)
                    
                    progress.advance(task)
                    
                    if progress_callback:
                        progress_callback(processed_job)
            else:
                # 𐑥𐑩𐑤𐑑𐑦-𐑞𐑮𐑧𐑛𐑦𐑛 𐑐𐑮𐑩𐑕𐑧𐑕𐑦𐑙
                with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                    # 𐑕𐑩𐑚𐑥𐑦𐑑 𐑷𐑤 𐑡𐑪𐑚𐑟
                    future_to_job = {
                        executor.submit(self._process_single_job, job): job 
                        for job in self.jobs
                    }
                    
                    # 𐑒𐑩𐑤𐑧𐑒𐑑 𐑮𐑦𐑟𐑳𐑤𐑑𐑟 𐑨𐑟 𐑞𐑱 𐑒𐑩𐑥𐑐𐑤𐑰𐑑
                    for future in as_completed(future_to_job):
                        processed_job = future.result()
                        
                        if processed_job.status == "completed":
                            self.completed_jobs.append(processed_job)
                        else:
                            self.failed_jobs.append(processed_job)
                        
                        progress.advance(task)
                        
                        if progress_callback:
                            progress_callback(processed_job)
        
        end_time = time.time()
        
        return {
            'completed': len(self.completed_jobs),
            'failed': len(self.failed_jobs),
            'total': len(self.jobs),
            'duration': end_time - start_time,
            'completed_jobs': self.completed_jobs,
            'failed_jobs': self.failed_jobs
        }
    
    def print_summary(self, results: Dict[str, Any]):
        """𐑐𐑮𐑦𐑯𐑑 𐑩 𐑞 𐑮𐑦𐑟𐑳𐑤𐑑𐑟 𐑕𐑩𐑥𐑼𐑦"""
        self.console.print(Panel("Batch Processing Summary", style="bold cyan"))
        
        # 𐑴𐑝𐑼𐑷𐑤 𐑕𐑑𐑩𐑑𐑦𐑕𐑑𐑦𐑒𐑕
        summary_table = Table(show_header=False, box=None)
        summary_table.add_column("Metric", style="bold cyan")
        summary_table.add_column("Value", style="white")
        
        summary_table.add_row("Total Files", str(results['total']))
        summary_table.add_row("Completed", f"[green]{results['completed']}[/green]")
        summary_table.add_row("Failed", f"[red]{results['failed']}[/red]")
        summary_table.add_row("Success Rate", f"{(results['completed'] / results['total'] * 100):.1f}%" if results['total'] > 0 else "0%")
        summary_table.add_row("Total Duration", f"{results['duration']:.2f} seconds")
        summary_table.add_row("Average Time/File", f"{(results['duration'] / results['total']):.2f} seconds" if results['total'] > 0 else "0 seconds")
        
        self.console.print(summary_table)
        
        # 𐑦𐑓 𐑞𐑻 𐑸 𐑓𐑱𐑤𐑛 𐑡𐑪𐑚𐑟, 𐑖𐑴 𐑞𐑧𐑥
        if self.failed_jobs:
            self.console.print("\n[red]Failed Jobs:[/red]")
            
            failed_table = Table(show_header=True)
            failed_table.add_column("File", style="cyan")
            failed_table.add_column("Error", style="red")
            failed_table.add_column("Duration", style="yellow")
            
            for job in self.failed_jobs:
                failed_table.add_row(
                    os.path.basename(job.input_file),
                    job.error[:100] + "..." if len(job.error) > 100 else job.error,
                    f"{job.get_duration():.2f}s"
                )
            
            self.console.print(failed_table)
    
    def clear_jobs(self):
        """𐑒𐑤𐑦𐑼 𐑷𐑤 𐑡𐑪𐑚𐑟 (𐑧𐑒𐑕𐑐𐑑 𐑒𐑩𐑥𐑐𐑤𐑰𐑑𐑦𐑛 𐑯 𐑓𐑱𐑤𐑛)"""
        self.jobs.clear()
    
    def get_job_statistics(self) -> Dict[str, Any]:
        """𐑜𐑧𐑑 𐑛𐑰𐑑𐑱𐑤𐑛 𐑞 𐑕𐑑𐑩𐑑𐑦𐑕𐑑𐑦𐑒𐑕 𐑦𐑯 𐑷𐑤 𐑡𐑪𐑚𐑟"""
        all_jobs = self.completed_jobs + self.failed_jobs
        
        if not all_jobs:
            return {}
        
        durations = [job.get_duration() for job in all_jobs if job.get_duration() > 0]
        
        return {
            'total_jobs': len(all_jobs),
            'completed_jobs': len(self.completed_jobs),
            'failed_jobs': len(self.failed_jobs),
            'success_rate': len(self.completed_jobs) / len(all_jobs) * 100 if all_jobs else 0,
            'avg_duration': sum(durations) / len(durations) if durations else 0,
            'min_duration': min(durations) if durations else 0,
            'max_duration': max(durations) if durations else 0,
            'total_duration': sum(durations) if durations else 0
        }